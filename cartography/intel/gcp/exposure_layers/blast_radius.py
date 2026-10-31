"""
GCP L5 (network half): where an instance can open connections to if it is compromised.

    (:GCPInstance)-[:CAN_NETWORK_REACH {ports, via}]->(:GCPSQLInstance)
        Cloud SQL private IP on a network the instance is in (private services access; VPC ingress
        firewall rules do not filter traffic to Cloud SQL).
    (:GCPInstance)-[:CAN_NETWORK_REACH {ports, via}]->(:GCPInstance)
        target's ingress firewall admits the source by source tag or source service account,
        evaluated first-match over the target's rules in the shared network, then narrowed by the
        firewall policies in force on it (an org "deny all ingress" removes the edge).

The identity half (instance -> service account -> roles) already exists in the graph.

ponytail: CIDR-sourced internal rules (default-allow-internal 10.128.0.0/9) are not turned into
edges: they would link every instance pair (N^2 edges); for the same reason a CIDR-sourced deny
does not cancel an identity allow here. Egress firewall rules, peering and Shared VPC stores in
other projects are not walked. O(instances^2) per network that has identity-sourced allows.
"""
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional

import neo4j

from cartography.intel.exposure.layers import CAN_NETWORK_REACH
from cartography.intel.exposure.layers import merge_reach_edges
from cartography.intel.exposure.layers import reach_summaries
from cartography.intel.exposure.layers import set_node_properties
from cartography.intel.exposure.layers import write_reach_counts
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.gcp.exposure_layers.network import admitting_rules
from cartography.intel.gcp.exposure_layers.network import Firewall
from cartography.intel.gcp.exposure_layers.network import from_cidr
from cartography.intel.gcp.exposure_layers.network import Instance
from cartography.intel.gcp.exposure_layers.network import INTRA_VPC
from cartography.intel.gcp.exposure_layers.network import levels_open
from cartography.intel.gcp.exposure_layers.network import NON_INTERNET
from cartography.intel.gcp.exposure_layers.network import open_ports
from cartography.intel.gcp.exposure_layers.network import PROJECT
from cartography.intel.gcp.exposure_layers.network import V4
from cartography.intel.gcp.exposure_layers.network import VpcFacts
from cartography.intel.gcp.exposure_layers.network import WORLD_CIDR

COMPUTE, SQL = "GCPInstance", "GCPSQLInstance"
VIA_PRIVATE_SERVICE_ACCESS = "private_service_access"
VIA_FIREWALL_IDENTITY = "firewall_source_tag_or_sa"
# Instance-to-instance traffic in one network, as a firewall policy source: any address, internal contexts.
_INTERNAL_WORLD = from_cidr(WORLD_CIDR[V4], frozenset({NON_INTERNET, INTRA_VPC}))

_SQL_QUERY = f"""
MATCH {PROJECT}-[:RESOURCE]->(n:GCPSQLInstance)
WHERE n.private_ip IS NOT NULL AND n.vpcNetworkID IS NOT NULL
RETURN n.id AS id, n.vpcNetworkID AS vpc, n.port AS port
"""
_SQL_IDS_QUERY = f"MATCH {PROJECT}-[:RESOURCE]->(n:GCPSQLInstance) RETURN n.id AS id"

_CLEANUP = f"""
MATCH {PROJECT}-[:RESOURCE]->(:GCPInstance)-[r:{CAN_NETWORK_REACH}]->()
WHERE r.lastupdated <> $UPDATE_TAG
DELETE r
"""


def sql_rows(instances: List[Instance], stores: List[Dict]) -> List[Dict]:
    rows = []
    for store in stores:
        port = store.get("port")
        ports = (PortSet.of(TCP, port, port) if port is not None else PortSet.of(TCP)).to_strings()
        for inst in instances:
            if store["vpc"] in inst.vpcs:
                rows.append({"src": inst.id, "dst": store["id"], "ports": ports, "via": VIA_PRIVATE_SERVICE_ACCESS})
    return rows


def from_identity(src: Instance) -> Callable[[Firewall], bool]:
    """
    VPC rule source matches the source instance by network tag or service account. Policy rules have
    neither; one matches when its source covers every address (0.0.0.0/0) in an internal context.

    ponytail: policy srcSecureTags, narrower CIDRs and the VPC_NETWORKS context are not matched to
    instances (no per-instance address or tag bindings here); such policy rules never cut an edge.
    """
    def match(fw: Firewall) -> bool:
        if fw.in_policy:
            return _INTERNAL_WORLD(fw)
        return bool(fw.source_tags & src.tags or fw.source_sas & src.sas)
    return match


def _identity_sourced(firewalls: List[Firewall]) -> bool:
    return any(fw.allow and (fw.source_tags or fw.source_sas) for fw in firewalls)


def pair_ports(vpc: VpcFacts, src: Instance, dst: Instance) -> PortSet:
    """Ports the VPC identity rules open from src to dst, narrowed by the firewall policies."""
    source = from_identity(src)
    ports = open_ports(vpc.firewalls, dst.tags, dst.sas, source)
    if ports.is_empty():
        return ports
    # Policies only narrow identity edges: their world-sourced allows would link every pair.
    return ports & levels_open(vpc.levels, dst.tags, dst.sas, source)


def admitted_by(vpc: VpcFacts, src: Instance, dst: Instance, ports: PortSet) -> Optional[str]:
    """First VPC identity allow rule admitting src to dst on these ports (a candidate, see admitting_rules)."""
    rules = admitting_rules([vpc.firewalls], dst, [from_identity(src)], ports)
    return rules[0].name if rules else None


def instance_rows(instances: List[Instance], vpcs: Dict[str, VpcFacts]) -> List[Dict]:
    rows = []
    for vpc_id, vpc in vpcs.items():
        if not vpc.visible or not _identity_sourced(vpc.firewalls):
            continue
        members = [i for i in instances if vpc_id in i.vpcs]
        for dst in members:
            for src in members:
                ports = pair_ports(vpc, src, dst) if src.id != dst.id else PortSet.empty()
                if ports.is_empty():
                    continue
                rows.append({
                    "src": src.id, "dst": dst.id, "ports": ports.to_strings(), "via": VIA_FIREWALL_IDENTITY,
                    "admitted_by": admitted_by(vpc, src, dst, ports),
                })
    return rows


def _merge_duplicates(rows: List[Dict]) -> List[Dict]:
    """An instance pair sharing two networks yields two rows; one edge carries the port union."""
    merged: Dict[tuple, Dict] = {}
    for row in rows:
        key = (row["src"], row["dst"])
        if key in merged:
            union = PortSet.parse(merged[key]["ports"]) | PortSet.parse(row["ports"])
            merged[key]["ports"] = union.to_strings()
            continue
        merged[key] = dict(row)
    return list(merged.values())


def sync(session: neo4j.Session, params: Dict, vpcs: Dict[str, VpcFacts], instances: Dict[str, Instance]) -> None:
    """
    Write this project's CAN_NETWORK_REACH edges, delete the ones not refreshed, then the summaries:
    network_reachable_data_stores on every instance, reverse counts on every Cloud SQL instance and
    instance. Run after the instances' internet_reachable is written (the counts read it).
    """
    computes = sorted(instances.values(), key=lambda i: i.id)
    stores = [dict(r) for r in session.run(_SQL_QUERY, **params)]
    tag = params["UPDATE_TAG"]
    edges = {
        SQL: _merge_duplicates(sql_rows(computes, stores)),
        COMPUTE: _merge_duplicates(instance_rows(computes, vpcs)),
    }
    for dst_label, rows in edges.items():
        merge_reach_edges(session, COMPUTE, dst_label, rows, tag)
    session.run(_CLEANUP, **params).consume()

    compute_ids = [c.id for c in computes]
    typed = [{**row, "dst_type": label} for label, rows in edges.items() for row in rows]
    set_node_properties(session, COMPUTE, reach_summaries(compute_ids, typed), evaluated_at=tag)
    write_reach_counts(session, SQL, [r["id"] for r in session.run(_SQL_IDS_QUERY, **params)], tag)
    write_reach_counts(session, COMPUTE, compute_ids, tag)
