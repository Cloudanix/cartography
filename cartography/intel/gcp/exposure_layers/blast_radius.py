"""
GCP L5 (network half): where an instance can open connections to if it is compromised.

    (:GCPInstance)-[:CAN_NETWORK_REACH {ports, via}]->(:GCPSQLInstance)
        Cloud SQL private IP on a network the instance is in (private services access; VPC ingress
        firewall rules do not filter traffic to Cloud SQL).
    (:GCPInstance)-[:CAN_NETWORK_REACH {ports, via}]->(:GCPInstance)
        target's ingress firewall admits the source by source tag or source service account,
        evaluated first-match over the target's rules in the shared network.

The identity half (instance -> service account -> roles) already exists in the graph.

ponytail: CIDR-sourced internal rules (default-allow-internal 10.128.0.0/9) are not turned into
edges: they would link every instance pair (N^2 edges); for the same reason a CIDR-sourced deny
does not cancel an identity allow here. Egress firewall rules, peering and Shared VPC stores in
other projects are not walked. O(instances^2) per network that has identity-sourced allows.
"""
from typing import Callable
from typing import Dict
from typing import List

import neo4j

from cartography.intel.exposure.layers import CAN_NETWORK_REACH
from cartography.intel.exposure.layers import merge_reach_edges
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.gcp.exposure_layers.network import Firewall
from cartography.intel.gcp.exposure_layers.network import Instance
from cartography.intel.gcp.exposure_layers.network import open_ports
from cartography.intel.gcp.exposure_layers.network import PROJECT
from cartography.intel.gcp.exposure_layers.network import VpcFacts

VIA_PRIVATE_SERVICE_ACCESS = "private_service_access"
VIA_FIREWALL_IDENTITY = "firewall_source_tag_or_sa"

_SQL_QUERY = f"""
MATCH {PROJECT}-[:RESOURCE]->(n:GCPSQLInstance)
WHERE n.private_ip IS NOT NULL AND n.vpcNetworkID IS NOT NULL
RETURN n.id AS id, n.vpcNetworkID AS vpc, n.port AS port
"""

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
    """Rule source matches the source instance by network tag or service account."""
    return lambda fw: bool(fw.source_tags & src.tags or fw.source_sas & src.sas)


def _identity_sourced(firewalls: List[Firewall]) -> bool:
    return any(fw.allow and (fw.source_tags or fw.source_sas) for fw in firewalls)


def instance_rows(instances: List[Instance], vpcs: Dict[str, VpcFacts]) -> List[Dict]:
    rows = []
    for vpc_id, vpc in vpcs.items():
        if not vpc.visible or not _identity_sourced(vpc.firewalls):
            continue
        members = [i for i in instances if vpc_id in i.vpcs]
        for dst in members:
            for src in members:
                if src.id == dst.id:
                    continue
                ports = open_ports(vpc.firewalls, dst.tags, dst.sas, from_identity(src))
                if ports.is_empty():
                    continue
                rows.append({"src": src.id, "dst": dst.id, "ports": ports.to_strings(), "via": VIA_FIREWALL_IDENTITY})
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
    """Write this project's CAN_NETWORK_REACH edges and delete the ones not refreshed."""
    computes = sorted(instances.values(), key=lambda i: i.id)
    stores = [dict(r) for r in session.run(_SQL_QUERY, **params)]
    tag = params["UPDATE_TAG"]
    merge_reach_edges(session, "GCPInstance", "GCPSQLInstance", _merge_duplicates(sql_rows(computes, stores)), tag)
    merge_reach_edges(session, "GCPInstance", "GCPInstance", _merge_duplicates(instance_rows(computes, vpcs)), tag)
    session.run(_CLEANUP, **params).consume()
