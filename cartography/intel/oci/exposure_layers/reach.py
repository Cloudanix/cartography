"""
OCI L1 (public) + L2 (internet reachable) per resource type. Each reader returns
{node_id: Reach} for EVERY node of its label in the compartment, so a node that stopped
being reachable is rewritten with false.

    OCIVnic / OCIInstance            VNIC public IP, subnet IGW route, security lists + VNIC NSGs
    OCIDbNode / OCIDbSystem          same, through the DB node VNICs
    OCILoadBalancer / OCINetwork...  not is_private, LB subnets + NSGs, listener ports
    instance behind a LB             reachable LB, backend port admitted by the instance rules
    OCIOKECluster / OCIApiGateway    public endpoint in a subnet (6443 / 443), legacy OKE endpoint
    OCIAutonomousDatabase            public endpoint (not dedicated), access control list
    OCIStorageBucket / OCIContainer- regional service endpoint, always answers on 443; L3 decides
    Repository

Blind spots (reported as reachable, never hidden): host firewalls, ports opened but not
listening, network firewalls / appliances in the route path (not ingested).
"""
from collections import defaultdict
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.exposure.ports import union_all
from cartography.intel.exposure.rules import is_world
from cartography.intel.oci.exposure_layers.network import any_source_open
from cartography.intel.oci.exposure_layers.network import COMPARTMENT
from cartography.intel.oci.exposure_layers.network import Network
from cartography.intel.oci.exposure_layers.network import TENANCY
from cartography.intel.oci.load_balancer import LOAD_BALANCER_LABEL
from cartography.intel.oci.load_balancer import NETWORK_LOAD_BALANCER_LABEL

Results = Dict[str, Dict[str, Reach]]  # label -> node id -> Reach

HTTPS = PortSet.of(TCP, 443, 443)
KUBERNETES_API = PortSet.of(TCP, 6443, 6443)
# Autonomous DB listeners: 1521 TLS, 1522 mTLS, 443 for ORDS / APEX / SQL Developer Web.
AUTONOMOUS_DB_PORTS = PortSet.of(TCP, 1521, 1522) | HTTPS
PUBLIC_BUCKET_ACCESS_TYPES = ("ObjectRead", "ObjectReadWithoutList")
SERVICE_ENDPOINT = "oci_service_endpoint"
PUBLIC_ENDPOINT = "public_endpoint"


def _merge(into: Reach, other: Reach) -> None:
    into.public_reasons |= other.public_reasons
    into.ports = into.ports | other.ports
    into.via |= other.via


def _add_paths(reach: Reach, paths: Dict[str, PortSet], service: Optional[PortSet] = None) -> None:
    for via, ports in paths.items():
        reach.add_path(ports & service if service is not None else ports, via)


# ---------------------------------------------------------------- VNIC owners


def vnic_reach(row: Dict, net: Network) -> Reach:
    reach = Reach()
    if not row.get("public_ip"):
        return reach
    reach.public_reasons.add("public_ip")
    _add_paths(reach, net.direct_paths([row.get("subnet_id")], row.get("nsg_ids") or []))
    return reach


def vnic_owners(rows: List[Dict], net: Network) -> Tuple[Dict[str, Reach], Dict[str, Reach]]:
    """Rows of (owner, VNIC) -> (owner id -> Reach, VNIC id -> Reach). Owner = union of its VNICs."""
    owners: Dict[str, Reach] = {}
    vnics: Dict[str, Reach] = {}
    for row in rows:
        owner = owners.setdefault(row["owner"], Reach())
        if row["id"] is None:
            continue
        vnic = vnics.setdefault(row["id"], vnic_reach(row, net))
        _merge(owner, vnic)
    return owners, vnics


_DB_NODE_VNIC_QUERY = f"""
MATCH {COMPARTMENT}(:OCIDbSystem)-[:HAS_DB_NODE]->(dn:OCIDbNode)
OPTIONAL MATCH (dn)-[:OCI_VNIC]->(v:OCIVnic)
RETURN dn.id AS owner, v.id AS id, v.public_ip AS public_ip, v.private_ip AS private_ip,
    v.subnet_id AS subnet_id, coalesce(v.nsg_ids, []) AS nsg_ids
"""

_DB_SYSTEM_QUERY = f"""
MATCH {COMPARTMENT}(s:OCIDbSystem)
OPTIONAL MATCH (s)-[:HAS_DB_NODE]->(dn:OCIDbNode)
RETURN s.id AS id, collect(dn.id) AS nodes
"""


def db_systems(rows: List[Dict], nodes: Dict[str, Reach]) -> Dict[str, Reach]:
    """A DB system is reachable when one of its nodes is."""
    out = {}
    for row in rows:
        reach = out[row["id"]] = Reach()
        for node_id in row["nodes"]:
            if node_id in nodes:
                _merge(reach, nodes[node_id])
    return out


# ---------------------------------------------------------------- load balancers

_LB_QUERY = f"""
MATCH {TENANCY}(c:OCICompartment)-[:RESOURCE]->(lb)
WHERE lb:{LOAD_BALANCER_LABEL} OR lb:{NETWORK_LOAD_BALANCER_LABEL}
RETURN lb.id AS id,
    CASE WHEN lb:{LOAD_BALANCER_LABEL} THEN '{LOAD_BALANCER_LABEL}' ELSE '{NETWORK_LOAD_BALANCER_LABEL}' END AS label,
    c.id = $OCI_COMPARTMENT_ID AS in_scope, coalesce(lb.is_private, false) AS private,
    coalesce(lb.subnet_ids, []) AS subnets, coalesce(lb.nsg_ids, []) AS nsgs,
    coalesce(lb.listener_targets, []) AS listeners, lb.backend_endpoints AS endpoints,
    coalesce(lb.backend_ips, []) + coalesce(lb.backend_target_ids, []) AS addresses
"""


def listener_ports(targets: List[str]) -> PortSet:
    """load_balancer.py listener_targets: '6:443', '17:53', 'any:0'; port 0 means every port."""
    ports = PortSet.empty()
    for target in targets:
        protocol, _, port = target.partition(":")
        number = int(port or 0) or None
        ports = ports | PortSet.of(protocol, number, number)
    return ports


def load_balancer_reach(row: Dict, net: Network) -> Reach:
    reach = Reach()
    if row["private"]:
        return reach
    reach.public_reasons.add("public_load_balancer")
    _add_paths(reach, net.direct_paths(row["subnets"], row["nsgs"]), listener_ports(row["listeners"]))
    return reach


def backend_endpoints(row: Dict) -> List[Tuple[str, Optional[int]]]:
    """
    (address, port) per backend; address is a private IP or an instance OCID. Graphs synced
    before backend_endpoints was ingested fall back to bare addresses with an unknown port.
    """
    if row["endpoints"] is None:
        return [(address, None) for address in row["addresses"]]
    pairs = []
    for endpoint in row["endpoints"]:
        address, _, port = endpoint.rpartition(":")
        pairs.append((address, int(port or 0) or None))
    return pairs


def _vnics_by_address(vnic_rows: List[Dict]) -> Dict[str, List[Dict]]:
    """Backends name an instance OCID (NLB target-id) or a private IP."""
    index: Dict[str, List[Dict]] = defaultdict(list)
    for row in vnic_rows:
        if row["id"] is None:
            continue
        index[row["owner"]].append(row)
        if row.get("private_ip"):
            index[row["private_ip"]].append(row)
    return index


def add_lb_backends(
    lb_rows: List[Dict], lbs: Dict[str, Reach], vnic_rows: List[Dict], instances: Dict[str, Reach], net: Network,
) -> None:
    """
    An instance behind a reachable LB is reachable on its backend port when its security lists
    or NSGs admit that port. IP backends must sit in one of the LB's VCNs (IPs repeat across VCNs).
    ponytail: any rule source counts, not only the LB subnet CIDR / NSG; stateless return of this
    internal hop is not checked.
    """
    index = _vnics_by_address(vnic_rows)
    for lb in lb_rows:
        lb_reach = lbs[lb["id"]]
        if lb_reach.ports.is_empty():
            continue
        vcns = {net.subnets[s].vcn_id for s in lb["subnets"] if s in net.subnets}
        for address, port in backend_endpoints(lb):
            target = union_all(PortSet.of(p, port, port) for p in lb_reach.ports.protocols())
            for vnic in index.get(address, []):
                subnet = net.subnets.get(vnic["subnet_id"] or "")
                if address == vnic["private_ip"] and vcns and (subnet is None or subnet.vcn_id not in vcns):
                    continue
                allowed = any_source_open(net.attachment_rules(vnic["subnet_id"], vnic["nsg_ids"]))
                instances[vnic["owner"]].add_path(target & allowed, f"lb:{lb['id']}")


# ---------------------------------------------------------------- endpoints and managed services

_OKE_QUERY = f"""
MATCH {COMPARTMENT}(n:OCIOKECluster)
RETURN n.id AS id, n.endpoint_subnet_id AS subnet, coalesce(n.endpoint_nsg_ids, []) AS nsgs,
    coalesce(n.endpoint_is_public_ip_enabled, false) OR coalesce(n.public_endpoint, '') <> '' AS public
"""

_API_GATEWAY_QUERY = f"""
MATCH {COMPARTMENT}(n:OCIApiGateway)
RETURN n.id AS id, n.subnet_id AS subnet, coalesce(n.nsg_ids, []) AS nsgs,
    coalesce(n.endpoint_type = 'PUBLIC', false) AS public
"""


def subnet_endpoints(rows: List[Dict], net: Network, service: PortSet) -> Dict[str, Reach]:
    """Public endpoints placed in a VCN subnet. No subnet = legacy OKE endpoint on the internet."""
    out = {}
    for row in rows:
        reach = out[row["id"]] = Reach()
        if not row["public"]:
            continue
        reach.public_reasons.add(PUBLIC_ENDPOINT)
        if not row["subnet"]:
            reach.add_path(service, PUBLIC_ENDPOINT)
            continue
        _add_paths(reach, net.direct_paths([row["subnet"]], row["nsgs"]), service)
    return out


_ADB_QUERY = f"""
MATCH {COMPARTMENT}(n:OCIAutonomousDatabase)
RETURN n.id AS id, coalesce(n.is_public, false) AS public, coalesce(n.is_dedicated, false) AS dedicated,
    coalesce(n.whitelisted_ips, []) AS acl
"""


def autonomous_databases(rows: List[Dict]) -> Dict[str, Reach]:
    """
    Public endpoint (no private endpoint subnet, not on dedicated infrastructure, which is
    VCN-only). An empty access control list admits every address.
    """
    out = {}
    for row in rows:
        reach = out[row["id"]] = Reach()
        if not row["public"] or row["dedicated"]:
            continue
        reach.public_reasons.add(PUBLIC_ENDPOINT)
        if not row["acl"] or any(is_world(c) for c in row["acl"]):
            reach.add_path(AUTONOMOUS_DB_PORTS, PUBLIC_ENDPOINT)
    return out


_BUCKET_QUERY = f"""
MATCH {COMPARTMENT}(n:OCIStorageBucket)
RETURN n.id AS id, coalesce(n.public_access_type IN {list(PUBLIC_BUCKET_ACCESS_TYPES)}, false) AS public,
    coalesce(n.read_par_expires_at, 0) > timestamp() AS par
"""

_REPOSITORY_QUERY = f"""
MATCH {COMPARTMENT}(n:OCIContainerRepository)
RETURN n.id AS id, coalesce(n.is_public, false) AS public, false AS par
"""


def service_endpoints(rows: List[Dict], public_reason: str) -> Dict[str, Reach]:
    """Object Storage / OCIR always answer on the regional endpoint; L3 decides who gets in."""
    out = {}
    for row in rows:
        reach = out[row["id"]] = Reach()
        if row["public"]:
            reach.public_reasons.add(public_reason)
        if row["par"]:
            reach.public_reasons.add("pre_authenticated_request")
        reach.add_path(HTTPS, SERVICE_ENDPOINT)
    return out


# ---------------------------------------------------------------- entry point


def _load_balancers(
    session: neo4j.Session, params: Dict, net: Network, vnic_rows: List[Dict], instances: Dict[str, Reach],
) -> Results:
    """LBs are read tenancy-wide: a LB in another compartment can front this compartment's instances."""
    rows = [dict(r) for r in session.run(_LB_QUERY, **params)]
    lbs = {row["id"]: load_balancer_reach(row, net) for row in rows}
    add_lb_backends(rows, lbs, vnic_rows, instances, net)
    out: Results = {LOAD_BALANCER_LABEL: {}, NETWORK_LOAD_BALANCER_LABEL: {}}
    for row in rows:
        if row["in_scope"]:
            out[row["label"]][row["id"]] = lbs[row["id"]]
    return out


def compute(session: neo4j.Session, params: Dict, net: Network, vnic_rows: List[Dict]) -> Results:
    """All OCI L1/L2 results for one compartment."""
    def q(query: str) -> List[Dict]:
        return [dict(r) for r in session.run(query, **params)]

    instances, vnics = vnic_owners(vnic_rows, net)
    db_nodes, db_vnics = vnic_owners(q(_DB_NODE_VNIC_QUERY), net)
    results: Results = _load_balancers(session, params, net, vnic_rows, instances)
    results.update({
        "OCIVnic": {**db_vnics, **vnics},
        "OCIInstance": instances,
        "OCIDbNode": db_nodes,
        "OCIDbSystem": db_systems(q(_DB_SYSTEM_QUERY), db_nodes),
        "OCIOKECluster": subnet_endpoints(q(_OKE_QUERY), net, KUBERNETES_API),
        "OCIApiGateway": subnet_endpoints(q(_API_GATEWAY_QUERY), net, HTTPS),
        "OCIAutonomousDatabase": autonomous_databases(q(_ADB_QUERY)),
        "OCIStorageBucket": service_endpoints(q(_BUCKET_QUERY), "public_access_type"),
        "OCIContainerRepository": service_endpoints(q(_REPOSITORY_QUERY), "public_repository"),
    })
    return results
