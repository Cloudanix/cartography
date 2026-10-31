"""
AWS L5 (network half): which data stores an instance can open a connection to.

    (:EC2Instance)-[:CAN_NETWORK_REACH {ports, via}]->(:RDSInstance|RedshiftCluster|ElasticacheCluster)

A store is reachable when one of its SG inbound rules covers its service port and admits the
instance, either by referencing one of the instance's SGs or by a CIDR holding one of its
private IPs, inside the same VPC. The identity half of the blast radius (instance profile ->
role -> permissions) already exists in the graph and is not duplicated here.

ponytail: same-VPC only; peering / TGW routes and NACLs between subnets are not walked.
O(instances x stores x rules) in Python; index by source SG if large accounts get slow.
"""
import ipaddress
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set

import neo4j

from cartography.intel.aws.exposure_layers.network import ACCOUNT
from cartography.intel.aws.exposure_layers.network import port_set
from cartography.intel.aws.exposure_layers.network import SgFacts
from cartography.intel.exposure.layers import CAN_NETWORK_REACH
from cartography.intel.exposure.layers import merge_reach_edges
from cartography.intel.exposure.ports import PortSet

_COMPUTE_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(i:EC2Instance)
OPTIONAL MATCH (i)-[:NETWORK_INTERFACE]->(eni:NetworkInterface)
OPTIONAL MATCH (eni)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(esg:EC2SecurityGroup)
OPTIONAL MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
WITH i, collect(DISTINCT esg.id) + collect(DISTINCT sg.id) AS sgs, collect(DISTINCT eni.private_ip_address) AS eni_ips
RETURN i.id AS id, sgs, [ip IN eni_ips + [i.privateipaddress] WHERE ip IS NOT NULL] AS ips
"""

# label -> port property
STORES = {"RDSInstance": "endpoint_port", "RedshiftCluster": "endpoint_port", "ElasticacheCluster": "port"}


def _store_query(label: str, port_prop: str) -> str:
    return f"""
    MATCH {ACCOUNT}-[:RESOURCE]->(n:{label})
    OPTIONAL MATCH (n)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
    RETURN n.id AS id, n.{port_prop} AS port, collect(DISTINCT sg.id) AS sgs
    """


def _cidr_holds(cidr: str, ips: Iterable[str]) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return any(ipaddress.ip_address(ip) in net for ip in ips)
    except ValueError:
        return False


def _vpcs(sg_ids: Iterable[str], sgs: Dict[str, SgFacts]) -> Set[str]:
    return {v for s in sg_ids if s in sgs for v in [sgs[s].vpc_id] if v}


def match_via(compute: Dict, store: Dict, sgs: Dict[str, SgFacts]) -> Optional[str]:
    """
    How `compute` gets through `store`'s security groups on its port, or None.
    An SG reference wins over a CIDR match so the answer does not depend on rule order.
    """
    a, b = _vpcs(compute["sgs"], sgs), _vpcs(store["sgs"], sgs)
    if a and b and not a & b:
        return None
    service = port_set(store.get("port")) or PortSet.everything()
    compute_sgs = set(compute["sgs"])
    via = None
    for sg_id in store["sgs"]:
        for ports, sources, cidrs in sgs[sg_id].rules if sg_id in sgs else []:
            if (ports & service).is_empty():
                continue
            if sources & compute_sgs:
                return "security_group"
            if any(_cidr_holds(c, compute["ips"]) for c in cidrs):
                via = "cidr"
    return via


def reach_rows(computes: List[Dict], stores: List[Dict], sgs: Dict[str, SgFacts]) -> List[Dict]:
    rows = []
    for store in stores:
        ports = (port_set(store.get("port")) or PortSet.everything()).to_strings()
        for compute in computes:
            via = match_via(compute, store, sgs)
            if via:
                rows.append({"src": compute["id"], "dst": store["id"], "ports": ports, "via": via})
    return rows


_CLEANUP = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(:EC2Instance)-[r:{CAN_NETWORK_REACH}]->()
WHERE r.lastupdated <> $UPDATE_TAG
DELETE r
"""


def sync(session: neo4j.Session, params: Dict, sgs: Dict[str, SgFacts]) -> None:
    computes = [dict(r) for r in session.run(_COMPUTE_QUERY, **params)]
    for label, port_prop in STORES.items():
        stores = [dict(r) for r in session.run(_store_query(label, port_prop), **params)]
        merge_reach_edges(session, "EC2Instance", label, reach_rows(computes, stores, sgs), params["UPDATE_TAG"])
    session.run(_CLEANUP, **params).consume()
