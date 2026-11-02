"""
GCP L5 (network half): where an instance can open connections to if it is compromised.

    (:GCPInstance)-[:CAN_NETWORK_REACH {ports, via}]->(:GCPSQLInstance)
        Cloud SQL private IP on a network the instance is in (private services access; VPC ingress
        firewall rules do not filter traffic to Cloud SQL).
    (:GCPInstance)-[:CAN_NETWORK_REACH {ports, via}]->(:GCPInstance)
        target's ingress firewall admits the source, evaluated over every rule level in force on
        the target (policies, VPC rules by priority, deny wins ties) with every rule source that
        holds the source instance: its network tags, service accounts, its internal address in a
        source range, or 0.0.0.0/0. So any higher-priority deny (tag, range or world) cuts the
        edge. The edge keeps only ports some lateral VPC allow admits:
            via firewall_source_tag_or_sa   source tag / service account rule
            via cidr                         non-world source range holding the source's internal
                                             IP (default-allow-internal 10.128.0.0/9)
        An identity rule wins `via` over a range rule, as an SG reference does on AWS.
        World-sourced allows alone make no edge: they would link every pair, and L2 already
        reports them as internet exposure.

The identity half (instance -> service account -> roles) already exists in the graph.

ponytail: O(instances^2) rule evaluations per network with a lateral allow; default-allow-internal
links every pair, so the largest network sets the cost (prod max 273 instances = 74k pairs,
2026-11-02). Cap per network or index rules by source if one passes ~1000 instances. Egress
firewall rules, peering and Shared VPC targets in other projects are not walked; IPv4 only.
"""
import ipaddress
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
from cartography.intel.exposure.ports import union_all
from cartography.intel.gcp.exposure_layers.network import admitting_rules
from cartography.intel.gcp.exposure_layers.network import applies_to
from cartography.intel.gcp.exposure_layers.network import Firewall
from cartography.intel.gcp.exposure_layers.network import from_cidr
from cartography.intel.gcp.exposure_layers.network import Instance
from cartography.intel.gcp.exposure_layers.network import INTRA_VPC
from cartography.intel.gcp.exposure_layers.network import levels_open
from cartography.intel.gcp.exposure_layers.network import NON_INTERNET
from cartography.intel.gcp.exposure_layers.network import PROJECT
from cartography.intel.gcp.exposure_layers.network import V4
from cartography.intel.gcp.exposure_layers.network import VpcFacts
from cartography.intel.gcp.exposure_layers.network import WORLD_CIDR

COMPUTE, SQL = "GCPInstance", "GCPSQLInstance"
VIA_PRIVATE_SERVICE_ACCESS = "private_service_access"
VIA_FIREWALL_IDENTITY = "firewall_source_tag_or_sa"
VIA_FIREWALL_CIDR = "cidr"
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


def _holds(cidr: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _is_world(cidr: str) -> bool:
    return cidr.endswith("/0")


def from_range(ip: Optional[str]) -> Callable[[Firewall], bool]:
    """VPC rule with a non-world source range holding `ip` (lateral traffic by address)."""
    def match(fw: Firewall) -> bool:
        if fw.in_policy or ip is None:
            return False
        return any(not _is_world(r) and _holds(r, ip) for r in fw.source_ranges)
    return match


def from_peer(src: Instance, ip: Optional[str]) -> Callable[[Firewall], bool]:
    """Every rule source holding src: policy rules as from_identity; VPC rules by identity, a range
    holding its address (0.0.0.0/0 included) or no source at all (GCP's 0.0.0.0/0 default)."""
    identity = from_identity(src)

    def match(fw: Firewall) -> bool:
        if fw.in_policy:
            return identity(fw)
        if identity(fw) or not fw.has_source:
            return True
        return ip is not None and any(_holds(r, ip) for r in fw.source_ranges)
    return match


def _lateral(fw: Firewall) -> bool:
    return fw.allow and bool(fw.source_tags or fw.source_sas or any(not _is_world(r) for r in fw.source_ranges))


def pair_edge(vpc: VpcFacts, src: Instance, ip: Optional[str], dst: Instance) -> Optional[Dict]:
    """
    Edge row src -> dst in one network, None when no lateral allow admits it. Ports: those every
    level opens to src, cut to the ports the lateral VPC allows (identity, then range) admit.
    """
    opened = levels_open(vpc.levels, dst.tags, dst.sas, from_peer(src, ip))
    if opened.is_empty():
        return None
    admitted, via, rule = PortSet.empty(), None, None
    for kind, matcher in ((VIA_FIREWALL_IDENTITY, from_identity(src)), (VIA_FIREWALL_CIDR, from_range(ip))):
        rules = admitting_rules([vpc.firewalls], dst, [matcher], opened)
        if rules:
            admitted = admitted | union_all(fw.ports for fw in rules)
            via, rule = via or kind, rule or rules[0].name
    ports = admitted & opened
    if ports.is_empty():
        return None
    return {"src": src.id, "dst": dst.id, "ports": ports.to_strings(), "via": via, "admitted_by": rule}


def _ip_in(inst: Instance, vpc_id: str) -> Optional[str]:
    return next((ip for v, ip in inst.internal_ips if v == vpc_id), None)


def instance_rows(instances: List[Instance], vpcs: Dict[str, VpcFacts]) -> List[Dict]:
    rows: List[Dict] = []
    for vpc_id, vpc in vpcs.items():
        lateral = [fw for fw in vpc.firewalls if _lateral(fw)] if vpc.visible else []
        if not lateral:
            continue
        members = [(i, _ip_in(i, vpc_id)) for i in instances if vpc_id in i.vpcs]
        for dst, _ in members:
            # Prefilter: a target no lateral allow applies to gets no edge, skip its N evaluations.
            if not any(applies_to(fw, dst.tags, dst.sas) for fw in lateral):
                continue
            edges = (pair_edge(vpc, src, ip, dst) for src, ip in members if src.id != dst.id)
            rows.extend(e for e in edges if e is not None)
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
    # Summary lists data stores only (as AWS / Azure / OCI): peer VMs stay edges, else an instance under
    # default-allow-internal would list every VM of its network as a "data store".
    typed = [{**row, "dst_type": SQL} for row in edges[SQL]]
    set_node_properties(session, COMPUTE, reach_summaries(compute_ids, typed), evaluated_at=tag)
    write_reach_counts(session, SQL, [r["id"] for r in session.run(_SQL_IDS_QUERY, **params)], tag)
    write_reach_counts(session, COMPUTE, compute_ids, tag)
