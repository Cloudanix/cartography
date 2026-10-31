"""
OCI L5 (network half): which databases an instance can open a connection to.

    (:OCIInstance)-[:CAN_NETWORK_REACH {ports, via}]->(:OCIDbSystem|OCIAutonomousDatabase)

A database is reachable when an ingress rule of its subnet security lists or its NSGs covers
its listener port and admits the instance, either by naming one of the instance's VNIC NSGs
or by a CIDR holding one of its private IPs, inside the same VCN. Autonomous Databases count
only with a private endpoint (subnet); public ones are covered by L2. The edges are also
summarised as node properties (the console export drops edge properties): the data stores
each instance reaches, and per data store how many instances (internet-exposed ones apart) reach it.

ponytail: same-VCN only; local peering / DRG routes and the instance's own egress rules are
not walked, stateless return paths are not checked. O(instances x databases x rules) in
Python; index rules by source if large tenancies get slow.

Identity half: instance principals act through dynamic groups, which are not ingested yet,
so OCI compute has no IAM blast radius in the graph (plan section 5.4).
"""
import ipaddress
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.exposure.layers import CAN_NETWORK_REACH
from cartography.intel.exposure.layers import merge_reach_edges
from cartography.intel.exposure.layers import reach_summaries
from cartography.intel.exposure.layers import set_node_properties
from cartography.intel.exposure.layers import write_reach_counts
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.oci.exposure_layers.network import COMPARTMENT
from cartography.intel.oci.exposure_layers.network import Network
from cartography.intel.oci.exposure_layers.network import TENANCY

INSTANCE_LABEL = "OCIInstance"
DEFAULT_DB_LISTENER_PORT = 1521
# Private endpoint listeners: 1521 TLS, 1522 mTLS.
AUTONOMOUS_DB_PORTS = (1521, 1522)

VIA_NSG = "network_security_group"
VIA_CIDR = "cidr"

# label -> query returning id, subnet, nsgs, port_min, port_max, in_scope (in this compartment).
# Databases are read tenancy-wide: an instance in this compartment may reach one in another.
STORES = {
    "OCIDbSystem": f"""
        MATCH {TENANCY}(c:OCICompartment)-[:RESOURCE]->(n:OCIDbSystem)
        WITH c, n, coalesce(n.listener_port, {DEFAULT_DB_LISTENER_PORT}) AS port
        RETURN n.id AS id, n.subnet_id AS subnet, coalesce(n.nsg_ids, []) AS nsgs, port AS port_min, port AS port_max,
            c.id = $OCI_COMPARTMENT_ID AS in_scope
    """,
    "OCIAutonomousDatabase": f"""
        MATCH {TENANCY}(c:OCICompartment)-[:RESOURCE]->(n:OCIAutonomousDatabase)
        WHERE n.subnet_id IS NOT NULL
        RETURN n.id AS id, n.subnet_id AS subnet, coalesce(n.nsg_ids, []) AS nsgs,
            {AUTONOMOUS_DB_PORTS[0]} AS port_min, {AUTONOMOUS_DB_PORTS[1]} AS port_max,
            c.id = $OCI_COMPARTMENT_ID AS in_scope
    """,
}


def _cidr_holds(cidr: str, ips: Iterable[str]) -> bool:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return any(ipaddress.ip_address(ip) in net for ip in ips)
    except ValueError:
        return False


def instances(vnic_rows: List[Dict], net: Network) -> List[Dict]:
    """Group VNIC rows per instance: private IPs, NSG ids and VCNs."""
    by_id: Dict[str, Dict] = {}
    for row in vnic_rows:
        inst = by_id.setdefault(row["owner"], {"id": row["owner"], "ips": [], "nsgs": set(), "vcns": set()})
        if row["id"] is None:
            continue
        if row.get("private_ip"):
            inst["ips"].append(row["private_ip"])
        inst["nsgs"].update(row["nsg_ids"] or [])
        subnet = net.subnets.get(row["subnet_id"] or "")
        if subnet and subnet.vcn_id:
            inst["vcns"].add(subnet.vcn_id)
    return list(by_id.values())


def match_via(instance: Dict, store: Dict, net: Network) -> Optional[Tuple[str, str]]:
    """
    (via, admitting security list / NSG id) for how `instance` gets through `store`'s filters
    on its port, or None. An NSG reference wins over a CIDR match so the answer does not depend
    on rule order; among CIDR matches the first filter in attachment order is named.
    """
    subnet = net.subnets.get(store["subnet"] or "")
    if subnet is None or subnet.vcn_id not in instance["vcns"]:
        return None
    service = PortSet.of(TCP, store["port_min"], store["port_max"])
    found = None
    for filter_id in (h["id"] for h in net.filter_hops(store["subnet"], store["nsgs"])):
        for rule in net.rules.get(filter_id, []):
            if not rule.ingress or (rule.ports & service).is_empty():
                continue
            if rule.peer in instance["nsgs"]:
                return VIA_NSG, filter_id
            if found is None and _cidr_holds(rule.peer, instance["ips"]):
                found = (VIA_CIDR, filter_id)
    return found


def reach_rows(computes: List[Dict], stores: List[Dict], net: Network, label: str) -> List[Dict]:
    """Edge rows for merge_reach_edges, shaped for reach_summaries too (dst_type, admitted_by)."""
    rows = []
    for store in stores:
        ports = PortSet.of(TCP, store["port_min"], store["port_max"]).to_strings()
        for instance in computes:
            match = match_via(instance, store, net)
            if match:
                rows.append({
                    "src": instance["id"], "dst": store["id"], "dst_type": label, "ports": ports,
                    "via": match[0], "admitted_by": match[1],
                })
    return rows


_CLEANUP = f"""
MATCH {COMPARTMENT}(:{INSTANCE_LABEL})-[r:{CAN_NETWORK_REACH}]->()
WHERE r.lastupdated <> $UPDATE_TAG
DELETE r
"""


def sync(session: neo4j.Session, params: Dict, net: Network, vnic_rows: List[Dict]) -> None:
    """
    Write CAN_NETWORK_REACH from this compartment's instances and drop stale ones, then the
    summaries: reachable data stores on every instance, reverse counts on this compartment's
    data stores. Run after the instances' internet_reachable is written.
    ponytail: counts see only edges written so far in this sync, so sources in compartments
    analysed after the store's own are missed; move the counts to a tenancy-level final step
    if cross-compartment reach matters.
    """
    tag = params["UPDATE_TAG"]
    computes = instances(vnic_rows, net)
    edges: List[Dict] = []
    in_scope: Dict[str, List[str]] = {}
    for label, query in STORES.items():
        stores = [dict(r) for r in session.run(query, **params)]
        rows = reach_rows(computes, stores, net, label)
        merge_reach_edges(session, INSTANCE_LABEL, label, rows, tag)
        edges.extend(rows)
        in_scope[label] = [s["id"] for s in stores if s["in_scope"]]
    session.run(_CLEANUP, **params).consume()
    set_node_properties(session, INSTANCE_LABEL, reach_summaries([c["id"] for c in computes], edges), evaluated_at=tag)
    for label, ids in in_scope.items():
        write_reach_counts(session, label, ids, tag)
