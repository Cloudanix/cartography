"""
AWS L5 (network half): which data stores an instance can open a connection to.

    (:EC2Instance)-[:CAN_NETWORK_REACH {ports, via}]->(:RDSInstance|RedshiftCluster|ElasticacheCluster)

A store is reachable when one of its SG inbound rules covers its service port and admits the
instance, either by referencing one of the instance's SGs or by a CIDR holding one of its
private IPs. The identity half of the blast radius (instance profile -> role -> permissions)
already exists in the graph and is not duplicated here.

    same VPC       via = security_group | cidr
    other VPC      via = peering:<pcx-id> | tgw:<tgw-id>, when the gateway joins both VPCs and
                   both sides route through it:
                     instance subnet route table: destination overlaps store subnet (or VPC) CIDR
                     store subnet route table:    destination holds an instance private IP

SG references count across same-region peering only (an AWS rule); over a TGW only CIDRs count.
A store without ingested subnets (Redshift, ElastiCache) uses every route table and CIDR of its
VPC: an upper bound.

ponytail: IPv4 only; NACLs between subnets are not walked (NACL rules are ingested, upgrade by
reusing first_match_open per subnet pair); longest-prefix match is not applied; TGW route tables
are not ingested, so default association and propagation are assumed (upgrade:
describe_transit_gateway_route_tables); TGW security group referencing (opt-in) is not modeled;
both ends must sit in the same account. O(instances x stores x rules) in Python; index by source
SG if large accounts get slow.
"""
import ipaddress
from dataclasses import dataclass
from itertools import product
from typing import Dict
from typing import FrozenSet
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import neo4j

from cartography.intel.aws.exposure_layers.network import ACCOUNT
from cartography.intel.aws.exposure_layers.network import port_set
from cartography.intel.aws.exposure_layers.network import SgFacts
from cartography.intel.exposure.layers import CAN_NETWORK_REACH
from cartography.intel.exposure.layers import merge_reach_edges
from cartography.intel.exposure.ports import PortSet

SG_VIA = "security_group"
CIDR_VIA = "cidr"
PEERING_VIA = "peering:"
TGW_VIA = "tgw:"

# (destination CIDR, pcx-* or tgw-* target)
Route = Tuple[str, str]
# (CIDRs, routes through a pcx / tgw) of a subnet or a whole VPC
Side = Tuple[List[str], List[Route]]


@dataclass(frozen=True)
class Gateway:
    target: str
    vpcs: FrozenSet[str]
    sg_refs: bool


@dataclass
class RouteFacts:
    subnets: Dict[str, Side]
    vpcs: Dict[str, Side]
    # via string ("peering:pcx-1") -> gateway
    gateways: Dict[str, Gateway]


_COMPUTE_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(i:EC2Instance)
OPTIONAL MATCH (i)-[:NETWORK_INTERFACE]->(eni:NetworkInterface)
OPTIONAL MATCH (eni)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(esg:EC2SecurityGroup)
OPTIONAL MATCH (eni)-[:PART_OF_SUBNET]->(sn:EC2Subnet)
OPTIONAL MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
WITH i, collect(DISTINCT esg.id) + collect(DISTINCT sg.id) AS sgs, collect(DISTINCT eni.private_ip_address) AS eni_ips,
    collect(DISTINCT sn.subnetid) AS subnets
RETURN i.id AS id, sgs, subnets, [ip IN eni_ips + [i.privateipaddress] WHERE ip IS NOT NULL] AS ips
"""

# label -> port property
STORES = {"RDSInstance": "endpoint_port", "RedshiftCluster": "endpoint_port", "ElasticacheCluster": "port"}


def _store_query(label: str, port_prop: str) -> str:
    # Only RDS has a subnet group in the graph; the other labels match nothing there.
    return f"""
    MATCH {ACCOUNT}-[:RESOURCE]->(n:{label})
    OPTIONAL MATCH (n)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
    OPTIONAL MATCH (n)-[:MEMBER_OF_DB_SUBNET_GROUP]->(:DBSubnetGroup)-[:CONNECTED_TO]->(sn:EC2Subnet)
    RETURN n.id AS id, n.{port_prop} AS port, collect(DISTINCT sg.id) AS sgs, collect(DISTINCT sn.subnetid) AS subnets
    """


# ---------------------------------------------------------------- pure evaluation


def _overlaps(cidr: str, ranges: Iterable[str]) -> bool:
    """True when `cidr` shares an address with one of `ranges` (CIDRs or bare IPs)."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        others = [ipaddress.ip_network(r, strict=False) for r in ranges]
    except (TypeError, ValueError):
        return False
    return any(o.version == net.version and net.overlaps(o) for o in others)


def _vpcs(sg_ids: Iterable[str], sgs: Dict[str, SgFacts]) -> Set[str]:
    return {v for s in sg_ids if s in sgs for v in [sgs[s].vpc_id] if v}


def sg_admits(compute: Dict, store: Dict, sgs: Dict[str, SgFacts], sg_refs: bool = True) -> Optional[str]:
    """
    How `compute` gets through `store`'s security groups on its port: SG_VIA, CIDR_VIA or None.
    An SG reference wins over a CIDR match so the answer does not depend on rule order.
    """
    service = port_set(store.get("port")) or PortSet.everything()
    compute_sgs = set(compute["sgs"]) if sg_refs else set()
    via = None
    for sg_id in store["sgs"]:
        for ports, sources, cidrs in sgs[sg_id].rules if sg_id in sgs else []:
            if (ports & service).is_empty():
                continue
            if sources & compute_sgs:
                return SG_VIA
            if any(_overlaps(c, compute["ips"]) for c in cidrs):
                via = CIDR_VIA
    return via


def _side(subnet_ids: Iterable[str], vpc_id: str, routes: RouteFacts) -> Side:
    """CIDRs and routes of one end: its subnets when known, else its whole VPC (upper bound)."""
    known = [routes.subnets[s] for s in subnet_ids if s in routes.subnets]
    if not known:
        return routes.vpcs.get(vpc_id, ([], []))
    return [c for cidrs, _ in known for c in cidrs], [r for _, rs in known for r in rs]


def _routes_through(routes: List[Route], target: str, ranges: List[str]) -> bool:
    return any(t == target and _overlaps(dst, ranges) for dst, t in routes)


def cross_vpc_path(
    compute: Dict, src_vpc: str, store: Dict, dst_vpc: str, routes: RouteFacts,
) -> Optional[Tuple[str, bool]]:
    """(via, SG references valid) of the first gateway both ends route through, or None."""
    src_cidrs, src_routes = _side(compute["subnets"], src_vpc, routes)
    dst_cidrs, dst_routes = _side(store["subnets"], dst_vpc, routes)
    for via, gw in sorted(routes.gateways.items()):
        if not {src_vpc, dst_vpc} <= gw.vpcs:
            continue
        there = _routes_through(src_routes, gw.target, dst_cidrs)
        back = _routes_through(dst_routes, gw.target, compute["ips"] or src_cidrs)
        if there and back:
            return via, gw.sg_refs
    return None


def match_via(
    compute: Dict, store: Dict, sgs: Dict[str, SgFacts], routes: Optional[RouteFacts] = None,
) -> Optional[str]:
    """Edge `via` for compute -> store, or None. Unknown VPCs are treated as the same VPC."""
    a, b = _vpcs(compute["sgs"], sgs), _vpcs(store["sgs"], sgs)
    if not (a and b and not a & b):
        return sg_admits(compute, store, sgs)
    if routes is None:
        return None
    for src_vpc, dst_vpc in product(sorted(a), sorted(b)):
        path = cross_vpc_path(compute, src_vpc, store, dst_vpc, routes)
        if path and sg_admits(compute, store, sgs, sg_refs=path[1]):
            return path[0]
    return None


def reach_rows(
    computes: List[Dict], stores: List[Dict], sgs: Dict[str, SgFacts], routes: Optional[RouteFacts] = None,
) -> List[Dict]:
    rows = []
    for store in stores:
        ports = (port_set(store.get("port")) or PortSet.everything()).to_strings()
        for compute in computes:
            via = match_via(compute, store, sgs, routes)
            if via:
                rows.append({"src": compute["id"], "dst": store["id"], "ports": ports, "via": via})
    return rows


# ---------------------------------------------------------------- graph reads

_ROUTE = "rt{.destination_cidr_block, .vpc_peering_connection_id, .transit_gateway_id}"
_ROUTE_FILTER = """(rt.vpc_peering_connection_id IS NOT NULL OR rt.transit_gateway_id IS NOT NULL)
    AND coalesce(rt.state, 'active') <> 'blackhole'"""

_SUBNET_ROUTES_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(s:EC2Subnet)
OPTIONAL MATCH (s)-[:HAS_EXPLICIT_ASSOCIATION|HAS_IMPLICIT_ASSOCIATION]->(:EC2RouteTableAssociation)
    <-[:HAS_ASSOCIATION]-(:EC2RouteTable)-[:MEMBER_OF_ROUTE_TABLE]->(rt:EC2Route)
WHERE {_ROUTE_FILTER}
RETURN s.subnetid AS id, [c IN [s.cidr_block] WHERE c IS NOT NULL] AS cidrs, collect({_ROUTE}) AS routes
"""

_VPC_ROUTES_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(v:AWSVpc)
OPTIONAL MATCH (v)-[:BLOCK_ASSOCIATION]->(b:AWSCidrBlock)
WITH v, collect(DISTINCT b.cidr_block) AS cidrs
OPTIONAL MATCH (v)<-[:MEMBER_OF_AWS_VPC]-(:EC2RouteTable)-[:MEMBER_OF_ROUTE_TABLE]->(rt:EC2Route)
WHERE {_ROUTE_FILTER}
RETURN v.id AS id, cidrs, collect({_ROUTE}) AS routes
"""

_PEERING_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(:AWSVpc)<-[:ACCEPTER_VPC|REQUESTER_VPC]-(p:AWSPeeringConnection{{status_code: 'active'}})
MATCH (p)-[:ACCEPTER_VPC]->(a:AWSVpc), (p)-[:REQUESTER_VPC]->(r:AWSVpc)
RETURN DISTINCT p.id AS id, [a.id, r.id] AS vpcs, coalesce(p.accepter_region = p.requester_region, false) AS sg_refs
"""

_TGW_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(v:AWSVpc)-[:RESOURCE]->(:AWSTransitGatewayAttachment{{state: 'available'}})
    -[:ATTACHED_TO]->(t:AWSTransitGateway)
RETURN t.tgw_id AS id, collect(DISTINCT v.id) AS vpcs, false AS sg_refs
"""


def _routes(rows: List[Dict]) -> List[Route]:
    out = []
    for r in rows:
        target = r.get("vpc_peering_connection_id") or r.get("transit_gateway_id")
        if r.get("destination_cidr_block") and target:
            out.append((r["destination_cidr_block"], target))
    return out


def read_routes(session: neo4j.Session, params: Dict) -> RouteFacts:
    def sides(query: str) -> Dict[str, Side]:
        return {r["id"]: (list(r["cidrs"]), _routes(r["routes"])) for r in session.run(query, **params)}

    gateways = {}
    for prefix, query in ((PEERING_VIA, _PEERING_QUERY), (TGW_VIA, _TGW_QUERY)):
        for r in session.run(query, **params):
            gateways[prefix + r["id"]] = Gateway(r["id"], frozenset(r["vpcs"]), r["sg_refs"])
    return RouteFacts(sides(_SUBNET_ROUTES_QUERY), sides(_VPC_ROUTES_QUERY), gateways)


_CLEANUP = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(:EC2Instance)-[r:{CAN_NETWORK_REACH}]->()
WHERE r.lastupdated <> $UPDATE_TAG
DELETE r
"""


def sync(session: neo4j.Session, params: Dict, sgs: Dict[str, SgFacts]) -> None:
    computes = [dict(r) for r in session.run(_COMPUTE_QUERY, **params)]
    routes = read_routes(session, params)
    for label, port_prop in STORES.items():
        stores = [dict(r) for r in session.run(_store_query(label, port_prop), **params)]
        merge_reach_edges(
            session, "EC2Instance", label, reach_rows(computes, stores, sgs, routes), params["UPDATE_TAG"],
        )
    session.run(_CLEANUP, **params).consume()
