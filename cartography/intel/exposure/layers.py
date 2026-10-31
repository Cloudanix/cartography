"""
Graph contract for the exposure layers: property names, auth states, result containers
and the writers every cloud uses. See docs/exposure-layers/plan.md section 3.
"""
import json
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set

import neo4j

from cartography.intel.exposure.ports import PortSet

# L1 / L2
PUBLIC_REASONS = "public_reasons"
INTERNET_REACHABLE = "internet_reachable"
INTERNET_REACHABLE_PORTS = "internet_reachable_ports"
INTERNET_REACHABLE_VIA = "internet_reachable_via"
# L3
ACCESS_AUTH = "access_auth"
ACCESS_AUTH_REASONS = "access_auth_reasons"
AUTH_NONE = "none"
AUTH_REQUIRED = "required"
AUTH_UNKNOWN = "unknown"
# L4
SOFTWARE_IDENTITY = "software_identity"
SOFTWARE_IDENTITY_SOURCE = "software_identity_source"
SOURCE_MANAGED_CONFIG = "managed_config"
SOURCE_IMAGE_NAME = "image_name"
# L5
CAN_NETWORK_REACH = "CAN_NETWORK_REACH"
NETWORK_REACHABLE_DATA_STORES = "network_reachable_data_stores"
NETWORK_REACHABLE_DATA_STORE_COUNT = "network_reachable_data_store_count"
NETWORK_REACHABLE_FROM_COUNT = "network_reachable_from_count"
NETWORK_REACHABLE_FROM_INTERNET_EXPOSED_COUNT = "network_reachable_from_internet_exposed_count"
# Context for the console (docs/console-exploitability-changes.md). Nested values are JSON text:
# neo4j properties cannot hold maps.
EXPOSURE_PATHS = "exposure_paths"
EXPOSURE_BLOCKED_BY = "exposure_blocked_by"
EXPOSURE_EVALUATED_AT = "exposure_evaluated_at"

# Hop kinds: one vocabulary across clouds so the console renders paths without per-cloud code.
HOP_INTERNET_GATEWAY = "internet_gateway"
HOP_ROUTE = "route"
HOP_NETWORK = "network"  # VPC / virtual network a path enters
HOP_SUBNET = "subnet"
HOP_NACL = "nacl"
HOP_SECURITY_GROUP = "security_group"
HOP_SECURITY_LIST = "security_list"
HOP_NSG = "nsg"
HOP_FIREWALL = "firewall"
HOP_FIREWALL_POLICY = "firewall_policy"
HOP_LISTENER = "listener"
HOP_TARGET_GROUP = "target_group"
HOP_BACKEND = "backend"
HOP_DNAT_RULE = "dnat_rule"
HOP_PUBLIC_IP = "public_ip"
HOP_SERVICE = "service"
# Why a public resource is not reachable (exposure_blocked_by[].reason).
BLOCK_NO_INTERNET_ROUTE = "no_internet_route"
BLOCK_PUBLIC_IP_PROHIBITED = "public_ip_prohibited"
BLOCK_NOT_ALLOWED = "not_allowed"  # no rule admits the world on any port
BLOCK_DENIED = "denied"  # a deny rule decides first
BLOCK_RETURN_PATH_DENIED = "return_path_denied"  # stateless filter drops the replies
BLOCK_NO_LISTENER = "no_listener"
BLOCK_UNKNOWN_NEXT_HOP = "unknown_next_hop"  # appliance / route we cannot see past

_WRITE_BATCH = 500


def hop(kind: str, hop_id: Optional[str], rule: Optional[str] = None) -> Dict[str, Any]:
    """One element of exposure_paths[].hops; rule is set only when the walker knows which rule decided."""
    out: Dict[str, Any] = {"hop": kind, "id": hop_id}
    if rule:
        out["rule"] = rule
    return out


def _dumps(value: object) -> str:
    return json.dumps(value, sort_keys=True)


@dataclass
class Reach:
    """
    L1 + L2 result for one node; several paths (direct, via LB, ...) accumulate.

    paths keeps per-entry-point ports and the hops each path passed, which the flat
    internet_reachable_ports / _via lose. blocked records why a public node got no path.
    """
    public_reasons: Set[str] = field(default_factory=set)
    ports: PortSet = field(default_factory=PortSet.empty)
    via: Set[str] = field(default_factory=set)
    paths: Dict[str, Dict] = field(default_factory=dict)
    blocked: List[Dict] = field(default_factory=list)

    def add_path(
        self, ports: PortSet, via: str, hops: Iterable[Dict] = (), entry: Optional[Dict] = None,
    ) -> None:
        if ports.is_empty():
            return
        self.ports = self.ports | ports
        self.via.add(via)
        path = self.paths.setdefault(via, {"via": via, "entry": entry, "ports": PortSet.empty(), "hops": []})
        path["ports"] = path["ports"] | ports
        path["entry"] = path["entry"] or entry
        path["hops"].extend(h for h in hops if h not in path["hops"])

    def block(
        self, kind: str, hop_id: Optional[str], reason: str,
        ports: Optional[PortSet] = None, detail: Optional[str] = None,
    ) -> None:
        """Record a hop that stopped a path; kept only if the node ends up public but unreachable."""
        entry: Dict[str, Any] = {**hop(kind, hop_id), "reason": reason}
        if ports is not None and not ports.is_empty():
            entry["ports"] = ports.to_strings()
        if detail:
            entry["detail"] = detail
        if entry not in self.blocked:
            self.blocked.append(entry)

    def _paths_json(self) -> str:
        return _dumps([
            {**p, "ports": p["ports"].to_strings()} for _, p in sorted(self.paths.items())
        ])

    def props(self) -> Dict:
        reachable = not self.ports.is_empty()
        explain_block = bool(self.public_reasons) and not reachable
        return {
            PUBLIC_REASONS: sorted(self.public_reasons),
            INTERNET_REACHABLE: reachable,
            INTERNET_REACHABLE_PORTS: self.ports.to_strings(),
            INTERNET_REACHABLE_VIA: sorted(self.via),
            EXPOSURE_PATHS: self._paths_json(),
            EXPOSURE_BLOCKED_BY: _dumps(self.blocked if explain_block else []),
        }


def auth_props(state: str, reasons: Iterable[str] = ()) -> Dict:
    return {ACCESS_AUTH: state, ACCESS_AUTH_REASONS: sorted(set(reasons))}


def software_props(identities: Iterable[Optional[str]], source: Optional[str]) -> Dict:
    ids = sorted({i for i in identities if i})
    return {SOFTWARE_IDENTITY: ids, SOFTWARE_IDENTITY_SOURCE: source if ids else None}


def set_node_properties(
    session: neo4j.Session, label: str, rows: List[Dict], key: str = "id",
    evaluated_at: Optional[int] = None,
) -> None:
    """
    SET n += row.props on (n:<label>{<key>: row.id}).

    :param label: node label; always a code constant, never user input (it is interpolated).
    :param rows: [{"id": ..., "props": {...}}]
    :param evaluated_at: the sync's update tag, stored as exposure_evaluated_at so the console can
        tell when the values were computed.
    """
    stamp = f", n.{EXPOSURE_EVALUATED_AT} = $evaluated_at" if evaluated_at is not None else ""
    query = f"UNWIND $rows AS row MATCH (n:`{label}`{{`{key}`: row.id}}) SET n += row.props{stamp}"
    for i in range(0, len(rows), _WRITE_BATCH):
        session.run(query, rows=rows[i:i + _WRITE_BATCH], evaluated_at=evaluated_at).consume()


def merge_reach_edges(
    session: neo4j.Session, src_label: str, dst_label: str, rows: List[Dict], update_tag: int,
) -> None:
    """MERGE (src)-[:CAN_NETWORK_REACH {ports, via}]->(dst) for rows [{src, dst, ports, via}]."""
    query = f"""
    UNWIND $rows AS row
    MATCH (a:`{src_label}`{{id: row.src}})
    MATCH (b:`{dst_label}`{{id: row.dst}})
    MERGE (a)-[r:{CAN_NETWORK_REACH}]->(b)
    SET r.ports = row.ports, r.via = row.via, r.lastupdated = $update_tag
    """
    for i in range(0, len(rows), _WRITE_BATCH):
        session.run(query, rows=rows[i:i + _WRITE_BATCH], update_tag=update_tag).consume()


def reach_summaries(src_ids: Iterable[str], edges: Iterable[Dict]) -> List[Dict]:
    """
    Rows for set_node_properties: every source gets the list of data stores it can reach (empty
    when none, so stale values are overwritten). The console reads this node property because the
    inventory export drops edge properties.

    :param edges: [{src, dst, dst_type, ports, via, admitted_by?}], dst_type being the data store label.
    """
    by_src: Dict[str, List[Dict]] = {s: [] for s in src_ids}
    for e in edges:
        item = {"id": e["dst"], "type": e["dst_type"], "ports": e["ports"], "via": e["via"]}
        if e.get("admitted_by"):
            item["admitted_by"] = e["admitted_by"]
        by_src.setdefault(e["src"], []).append(item)
    return [
        {
            "id": src, "props": {
                NETWORK_REACHABLE_DATA_STORES: _dumps(sorted(items, key=lambda i: (i["type"], i["id"]))),
                NETWORK_REACHABLE_DATA_STORE_COUNT: len(items),
            },
        }
        for src, items in by_src.items()
    ]


def write_reach_counts(session: neo4j.Session, dst_label: str, dst_ids: List[str], update_tag: int) -> None:
    """
    On each data store: how many sources can reach it, and how many of those are themselves
    internet-reachable (the indirect exposure a database page should show). Run after the sources'
    internet_reachable and this run's edges are written.
    """
    query = f"""
    UNWIND $ids AS id
    MATCH (d:`{dst_label}`{{id: id}})
    OPTIONAL MATCH (s)-[r:{CAN_NETWORK_REACH}]->(d) WHERE r.lastupdated = $update_tag
    WITH d, count(s) AS total, count(CASE WHEN s.{INTERNET_REACHABLE} THEN 1 END) AS exposed
    SET d.{NETWORK_REACHABLE_FROM_COUNT} = total,
        d.{NETWORK_REACHABLE_FROM_INTERNET_EXPOSED_COUNT} = exposed,
        d.{EXPOSURE_EVALUATED_AT} = $update_tag
    """
    for i in range(0, len(dst_ids), _WRITE_BATCH):
        session.run(query, ids=dst_ids[i:i + _WRITE_BATCH], update_tag=update_tag).consume()
