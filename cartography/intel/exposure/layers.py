"""
Graph contract for the exposure layers: property names, auth states, result containers
and the writers every cloud uses. See docs/exposure-layers/plan.md section 3.
"""
from dataclasses import dataclass
from dataclasses import field
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

_WRITE_BATCH = 500


@dataclass
class Reach:
    """L1 + L2 result for one node; several paths (direct, via LB, ...) accumulate."""
    public_reasons: Set[str] = field(default_factory=set)
    ports: PortSet = field(default_factory=PortSet.empty)
    via: Set[str] = field(default_factory=set)

    def add_path(self, ports: PortSet, via: str) -> None:
        if ports.is_empty():
            return
        self.ports = self.ports | ports
        self.via.add(via)

    def props(self) -> Dict:
        return {
            PUBLIC_REASONS: sorted(self.public_reasons),
            INTERNET_REACHABLE: not self.ports.is_empty(),
            INTERNET_REACHABLE_PORTS: self.ports.to_strings(),
            INTERNET_REACHABLE_VIA: sorted(self.via),
        }


def auth_props(state: str, reasons: Iterable[str] = ()) -> Dict:
    return {ACCESS_AUTH: state, ACCESS_AUTH_REASONS: sorted(set(reasons))}


def software_props(identities: Iterable[Optional[str]], source: Optional[str]) -> Dict:
    ids = sorted({i for i in identities if i})
    return {SOFTWARE_IDENTITY: ids, SOFTWARE_IDENTITY_SOURCE: source if ids else None}


def set_node_properties(
    session: neo4j.Session, label: str, rows: List[Dict], key: str = "id",
) -> None:
    """
    SET n += row.props on (n:<label>{<key>: row.id}).

    :param label: node label; always a code constant, never user input (it is interpolated).
    :param rows: [{"id": ..., "props": {...}}]
    """
    query = f"UNWIND $rows AS row MATCH (n:`{label}`{{`{key}`: row.id}}) SET n += row.props"
    for i in range(0, len(rows), _WRITE_BATCH):
        session.run(query, rows=rows[i:i + _WRITE_BATCH]).consume()


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
