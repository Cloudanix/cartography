"""
GCP network facts for the exposure layers: VPC firewall evaluation and the internet route gate.

Path model for an instance, per IP family:
    internet -> external IP (accessConfig natIP / IPv6 access config)
             -> VPC route 0.0.0.0/0 (::/0) -> default-internet-gateway applying to the instance
             -> VPC firewall ingress rules (priority order, deny wins ties, implied deny last)
             -> port

Firewall rules apply to an instance in the same network when they have no targets, or their
target tags / target service accounts match the instance.

Blind spots (reported as reachable / not hidden): hierarchical and network firewall policies
(evaluated before VPC rules, not ingested), host firewalls, ports opened but not listening.
"""
import ipaddress
from dataclasses import dataclass
from dataclasses import field
from typing import Callable
from typing import Dict
from typing import FrozenSet
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.exposure.ports import union_all
from cartography.intel.exposure.rules import FirewallRule
from cartography.intel.exposure.rules import first_match_open

PROJECT = (
    "(:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:GCPOrganization{id: $GCP_ORGANIZATION_ID})"
    "-[:OWNER]->(:GCPProject{id: $GCP_PROJECT_ID})"
)
V4, V6 = "v4", "v6"
WORLD_CIDR = {V4: "0.0.0.0/0", V6: "::/0"}
HTTPS = PortSet.of(TCP, 443, 443)
INTERNET_GATEWAY = "default-internet-gateway"
DEFAULT_PRIORITY = 1000
INGRESS = "INGRESS"
# Google Front End ranges: proxy load balancers (HTTP(S), SSL, TCP proxy) reach backends from here,
# never from the client address. https://cloud.google.com/load-balancing/docs/firewall-rules
GFE_RANGES = ("130.211.0.0/22", "35.191.0.0/16")
# Target kinds whose forwarding rules terminate the client connection at a proxy.
PROXY_TARGETS = ("targetHttpProxies", "targetHttpsProxies", "targetSslProxies", "targetTcpProxies")


@dataclass(frozen=True)
class Firewall:
    """One VPC ingress firewall rule; GCP rules are either all-allow or all-deny."""
    allow: bool
    ports: PortSet
    priority: int = DEFAULT_PRIORITY
    source_ranges: Tuple[str, ...] = ()
    source_tags: FrozenSet[str] = frozenset()
    source_sas: FrozenSet[str] = frozenset()
    target_tags: FrozenSet[str] = frozenset()
    target_sas: FrozenSet[str] = frozenset()

    @property
    def has_source(self) -> bool:
        return bool(self.source_ranges or self.source_tags or self.source_sas)


@dataclass
class VpcFacts:
    """
    visible: firewalls of this network are synced by this workspace (else the verdict is unknown).
    routes: [{dest_range, priority, tags, next_hop_gateway}]; empty means routes were not ingested.
    """
    visible: bool
    firewalls: List[Firewall] = field(default_factory=list)
    routes: List[Dict] = field(default_factory=list)


# ---------------------------------------------------------------- pure evaluation


def entry_ports(entry: str) -> PortSet:
    """
    Ports of one stored firewall entry (compute.firewall_entry_strings).

    >>> entry_ports("tcp:8000-9000").to_strings()
    ['tcp:8000-9000']
    >>> entry_ports("all").to_strings()
    ['tcp:0-65535', 'udp:0-65535']
    """
    protocol, _, rng = entry.partition(":")
    if not rng:
        return PortSet.of(protocol)
    lo, _, hi = rng.partition("-")
    return PortSet.of(protocol, int(lo), int(hi or lo))


def firewall_from_row(row: Dict) -> Optional[Firewall]:
    """A graph row (GCPFirewall properties) as a Firewall; None for disabled or egress rules."""
    if row.get("disabled") or (row.get("direction") or INGRESS) != INGRESS:
        return None
    allowed = row.get("allowed_entries") or []
    entries = allowed or row.get("denied_entries") or []
    return Firewall(
        allow=bool(allowed),
        ports=union_all(entry_ports(e) for e in entries),
        priority=int(row["priority"]) if row.get("priority") is not None else DEFAULT_PRIORITY,
        source_ranges=tuple(row.get("source_ranges") or ()),
        source_tags=frozenset(row.get("source_tags") or ()),
        source_sas=frozenset(row.get("source_service_accounts") or ()),
        target_tags=frozenset(row.get("target_tags") or ()),
        target_sas=frozenset(row.get("target_service_accounts") or ()),
    )


def applies_to(fw: Firewall, tags: FrozenSet[str], sas: FrozenSet[str]) -> bool:
    """Targets: service accounts, else tags, else every instance of the network."""
    if fw.target_sas:
        return bool(fw.target_sas & sas)
    if fw.target_tags:
        return bool(fw.target_tags & tags)
    return True


def _contains(cidr: str, source: str) -> bool:
    try:
        inner, outer = ipaddress.ip_network(source, strict=False), ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False
    return inner.version == outer.version and inner.network_address in outer and inner.broadcast_address in outer


def from_cidr(source: str) -> Callable[[Firewall], bool]:
    """
    Rule source matches when a source range covers the whole `source` block. An ingress rule
    with no source at all defaults to 0.0.0.0/0 in GCP.
    """
    is_v4_world = source == WORLD_CIDR[V4]

    def match(fw: Firewall) -> bool:
        if not fw.has_source:
            return is_v4_world
        return any(_contains(cidr, source) for cidr in fw.source_ranges)
    return match


def open_ports(
    firewalls: Iterable[Firewall], tags: FrozenSet[str], sas: FrozenSet[str],
    source: Callable[[Firewall], bool],
) -> PortSet:
    """Ports the network's ingress rules open to `source` on an instance with these tags / SAs."""
    rules = [
        FirewallRule(fw.ports, world=source(fw), allow=fw.allow, priority=fw.priority)
        for fw in firewalls if applies_to(fw, tags, sas)
    ]
    return first_match_open(rules)


def internet_route(routes: List[Dict], tags: FrozenSet[str], family: str) -> Optional[bool]:
    """
    Does the instance's default route lead to the internet gateway? None when routes were not
    ingested for this network (do not block on what we cannot see).

    ponytail: only /0 routes are compared (lowest priority number wins, ties count if any is the
    gateway); a more specific route sending part of the internet to an appliance is not modelled.
    """
    if not routes:
        return None
    defaults = [
        r for r in routes
        if r.get("dest_range") == WORLD_CIDR[family] and (not r.get("tags") or set(r["tags"]) & tags)
    ]
    if not defaults:
        return False
    best = min(int(r.get("priority") or 0) for r in defaults)
    return any(
        str(r.get("next_hop_gateway") or "").endswith(INTERNET_GATEWAY)
        for r in defaults if int(r.get("priority") or 0) == best
    )


def forwarding_ports(protocol: Optional[str], port_range: Optional[str], ports: Optional[List[str]]) -> PortSet:
    """
    Front-end ports of a forwarding rule. L3_DEFAULT carries every protocol; a rule with
    neither ports nor portRange forwards every port.
    """
    proto = "all" if str(protocol or "").upper() == "L3_DEFAULT" else protocol
    specs = list(ports or []) or ([port_range] if port_range else [])
    if not specs:
        return PortSet.of(proto)
    return union_all(entry_ports(f"{proto}:{spec}") for spec in specs)


def is_proxy(target: Optional[str]) -> bool:
    return any(f"/{kind}/" in str(target or "") for kind in PROXY_TARGETS)


# ---------------------------------------------------------------- graph reads

# Firewalls count only from networks owned by a project of this organization that this workspace
# syncs (same rule as gcp_compute_instance_analysis.json); other networks are "not visible".
_VPC_QUERY = f"""
MATCH {PROJECT}-[:RESOURCE]->(:GCPInstance)-[:MEMBER_OF_GCP_VPC]->(vpc:GCPVpc)
WITH DISTINCT vpc
OPTIONAL MATCH (:GCPOrganization{{id: $GCP_ORGANIZATION_ID}})-[:OWNER]->(owner:GCPProject)-[:RESOURCE]->(vpc)
WHERE $WORKSPACE_ID IN coalesce(owner.workspace_ids, [])
WITH vpc, count(owner) > 0 AS visible
OPTIONAL MATCH (vpc)-[:RESOURCE]->(fw:GCPFirewall)
WITH vpc, visible, collect(fw {{.*}}) AS firewalls
OPTIONAL MATCH (vpc)-[:RESOURCE]->(rt:GCPRoute)
RETURN vpc.id AS id, visible, firewalls,
    collect(rt {{.dest_range, .priority, .tags, .next_hop_gateway}}) AS routes
"""


@dataclass(frozen=True)
class Instance:
    id: str
    running: bool
    public_v4: bool = False
    public_v6: bool = False
    vpcs: Tuple[str, ...] = ()
    tags: FrozenSet[str] = frozenset()
    sas: FrozenSet[str] = frozenset()


def instance_open(
    inst: Instance, vpcs: Dict[str, VpcFacts], sources: Iterable[str], family: Optional[str] = None,
) -> Tuple[PortSet, bool]:
    """
    Ports the instance's networks open to any of `sources`, and whether some network's firewalls
    were not visible (then every port counts: fail-safe, as the legacy exposure job does).
    With `family`, a network whose default route avoids the internet gateway opens nothing.

    ponytail: union over NICs; a multi-NIC instance gets every network's rules for every address.
    """
    sources = list(sources)
    ports, unresolved = PortSet.empty(), False
    for vpc_id in inst.vpcs:
        vpc = vpcs.get(vpc_id)
        if vpc is None or not vpc.visible:
            unresolved, opened = True, PortSet.everything()
        else:
            opened = union_all(open_ports(vpc.firewalls, inst.tags, inst.sas, from_cidr(s)) for s in sources)
        if family and vpc is not None and internet_route(vpc.routes, inst.tags, family) is False:
            opened = PortSet.empty()
        ports = ports | opened
    return ports, unresolved


_INSTANCE_QUERY = f"""
MATCH {PROJECT}-[:RESOURCE]->(i:GCPInstance)
OPTIONAL MATCH (i)-[:MEMBER_OF_GCP_VPC]->(vpc:GCPVpc)
WITH i, collect(DISTINCT vpc.id) AS vpcs
OPTIONAL MATCH (i)-[:TAGGED]->(t:GCPNetworkTag)
WITH i, vpcs, collect(DISTINCT t.value) AS tags
OPTIONAL MATCH (i)-[:USES]->(sa:GCPServiceAccount)
WITH i, vpcs, tags, collect(DISTINCT sa.email) AS sas
OPTIONAL MATCH (i)-[:NETWORK_INTERFACE]->(:GCPNetworkInterface)-[:RESOURCE]->(ac:GCPNicAccessConfig)
WITH i, vpcs, tags, sas, collect(DISTINCT ac.public_ip) AS ac_ips
RETURN i.id AS id, i.status AS status, vpcs, tags, sas, i.ipv6_nat_ip AS ipv6,
    [ip IN ac_ips + [i.natIP] WHERE ip IS NOT NULL] AS public_ips
"""


def instance_from_row(row: Dict) -> Instance:
    return Instance(
        id=row["id"],
        # An unknown status (older sync) is not a reason to hide a path.
        running=row.get("status") in (None, "RUNNING"),
        public_v4=bool(row.get("public_ips")),
        public_v6=bool(row.get("ipv6")),
        vpcs=tuple(sorted(row.get("vpcs") or ())),
        tags=frozenset(row.get("tags") or ()),
        sas=frozenset(row.get("sas") or ()),
    )


def read_instances(session: neo4j.Session, params: Dict) -> Dict[str, Instance]:
    return {row["id"]: instance_from_row(dict(row)) for row in session.run(_INSTANCE_QUERY, **params)}


def vpc_facts_from_row(row: Dict) -> VpcFacts:
    # Firewalls loaded before allowed_entries existed would read as "no rule": treat the network as
    # not visible until its next sync instead of reporting an implied deny.
    stale = any(fw.get("allowed_entries") is None for fw in row["firewalls"])
    firewalls = [fw for fw in (firewall_from_row(r) for r in row["firewalls"]) if fw is not None]
    return VpcFacts(visible=bool(row["visible"]) and not stale, firewalls=firewalls, routes=row["routes"])


def read_vpcs(session: neo4j.Session, params: Dict) -> Dict[str, VpcFacts]:
    return {row["id"]: vpc_facts_from_row(dict(row)) for row in session.run(_VPC_QUERY, **params)}
