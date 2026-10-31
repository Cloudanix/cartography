"""
GCP network facts for the exposure layers: firewall evaluation and the internet route gate.

Path model for an instance, per IP family:
    internet -> external IP (accessConfig natIP / IPv6 access config)
             -> VPC route 0.0.0.0/0 (::/0) -> default-internet-gateway applying to the instance
             -> firewall levels, in Cloud NGFW evaluation order:
                  org policy -> folder policies (top-down) -> [system policies]
                  -> VPC firewall rules (priority order, deny wins ties) and the global network
                     firewall policy, ordered by the network's networkFirewallPolicyEnforcementOrder
                  -> implied deny
             -> port
https://cloud.google.com/firewall/docs/firewall-policies-rule-eval-order

In a level, allow / deny ends evaluation; goto_next or no matching rule moves to the next level.
VPC rules apply to an instance when they have no targets, or their target tags / target service
accounts match it; policy rules target service accounts or secure tags.

Blind spots (reported as reachable / not hidden): regional network firewall policies, host
firewalls, ports opened but not listening. Without policy data (call refused, older sync) only
the VPC rules decide, as before policies were ingested.
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
from cartography.intel.exposure.rules import tiered_open

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

# Firewall policy source network contexts. GFE and health-check traffic is non-internet:
# https://cloud.google.com/firewall/docs/understand-network-contexts
INTERNET, NON_INTERNET, INTRA_VPC, UNSPECIFIED = "INTERNET", "NON_INTERNET", "INTRA_VPC", "UNSPECIFIED"
# Policy rule actions. ponytail: apply_security_profile_group hands the packet to an L7 inspection
# endpoint that may still drop it; counted as allow (upper bound). Upgrade: ingest security profiles.
ALLOW_ACTIONS = ("allow", "apply_security_profile_group")
DENY, GOTO_NEXT = "deny", "goto_next"
# Policy types evaluated before the VPC rules whatever the enforcement order, in this order.
POLICY_TIERS = {"HIERARCHY": 0, "SYSTEM": 1}
NETWORK_POLICY_TIER = len(POLICY_TIERS)
BEFORE_CLASSIC_FIREWALL = "BEFORE_CLASSIC_FIREWALL"


@dataclass(frozen=True)
class Firewall:
    """
    One ingress rule: a VPC firewall rule (all-allow or all-deny) or a firewall policy rule
    (in_policy; may be goto_next, may carry a network context, unresolved sources, secure tag targets).
    """
    allow: bool
    ports: PortSet
    priority: int = DEFAULT_PRIORITY
    source_ranges: Tuple[str, ...] = ()
    source_tags: FrozenSet[str] = frozenset()
    source_sas: FrozenSet[str] = frozenset()
    target_tags: FrozenSet[str] = frozenset()
    target_sas: FrozenSet[str] = frozenset()
    goto_next: bool = False
    in_policy: bool = False
    network_context: Optional[str] = None
    other_sources: bool = False
    secure_tag_target: bool = False

    @property
    def has_source(self) -> bool:
        return bool(self.source_ranges or self.source_tags or self.source_sas or self.other_sources)


Level = List[Firewall]


@dataclass
class VpcFacts:
    """
    visible: firewalls of this network are synced by this workspace (else the verdict is unknown).
    routes: [{dest_range, priority, tags, next_hop_gateway}]; empty means routes were not ingested.
    policies_before / policies_after: firewall policies (one level each) evaluated before / after the
    VPC rules; empty when the network has none or they were not ingested.
    """
    visible: bool
    firewalls: List[Firewall] = field(default_factory=list)
    routes: List[Dict] = field(default_factory=list)
    policies_before: List[Level] = field(default_factory=list)
    policies_after: List[Level] = field(default_factory=list)

    @property
    def levels(self) -> List[Level]:
        return self.policies_before + [self.firewalls] + self.policies_after


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


def policy_rule_from_row(row: Dict) -> Optional[Firewall]:
    """A GCPFirewallPolicyRule row as a Firewall; None for an action that decides nothing about ingress."""
    action = row.get("action")
    if action not in ALLOW_ACTIONS and action not in (DENY, GOTO_NEXT):
        return None
    context = row.get("network_context")
    return Firewall(
        allow=action in ALLOW_ACTIONS,
        goto_next=action == GOTO_NEXT,
        ports=union_all(entry_ports(e) for e in row.get("entries") or []),
        priority=int(row.get("priority") or 0),
        source_ranges=tuple(row.get("source_ranges") or ()),
        target_sas=frozenset(row.get("target_service_accounts") or ()),
        in_policy=True,
        network_context=None if context == UNSPECIFIED else context,
        other_sources=bool(row.get("other_sources")),
        secure_tag_target=bool(row.get("target_secure_tags")),
    )


def policy_levels(rows: List[Dict], enforcement_order: Optional[str]) -> Tuple[List[Level], List[Level]]:
    """
    Policy rule rows grouped into one level per policy, split into (before VPC rules, after VPC rules).
    Hierarchical then system policies always come first; the network policy follows the VPC rules unless
    the network's enforcement order is BEFORE_CLASSIC_FIREWALL.

    ponytail: hierarchical policies keep the API response order (org first, folders top-down, as
    `gcloud compute networks get-effective-firewalls` prints them); the response has no level field.
    """
    by_policy: Dict[Tuple[int, int], Level] = {}
    for row in rows:
        rule = policy_rule_from_row(row)
        if rule is None:
            continue
        tier = POLICY_TIERS.get(row.get("policy_type") or "", NETWORK_POLICY_TIER)
        by_policy.setdefault((tier, int(row.get("policy_order") or 0)), []).append(rule)
    ordered = sorted(by_policy.items())
    first = [level for (tier, _), level in ordered if tier < NETWORK_POLICY_TIER]
    network = [level for (tier, _), level in ordered if tier >= NETWORK_POLICY_TIER]
    return (first + network, []) if enforcement_order == BEFORE_CLASSIC_FIREWALL else (first, network)


def applies_to(fw: Firewall, tags: FrozenSet[str], sas: FrozenSet[str]) -> bool:
    """
    Targets: service accounts, else secure tags, else network tags, else every instance of the network.

    ponytail: secure tag bindings are not ingested. A secure-tag-targeted rule counts unless it denies,
    so a deny is never claimed without proof; a tagged goto_next that in truth skips the instance (which a
    later allow in the same policy would admit) is the remaining gap. Upgrade: ingest tag bindings.
    """
    if fw.target_sas:
        return bool(fw.target_sas & sas)
    if fw.secure_tag_target:
        return fw.allow or fw.goto_next
    if fw.target_tags:
        return bool(fw.target_tags & tags)
    return True


def _contains(cidr: str, source: str) -> bool:
    try:
        inner, outer = ipaddress.ip_network(source, strict=False), ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False
    return inner.version == outer.version and inner.network_address in outer and inner.broadcast_address in outer


def from_cidr(source: str, contexts: Optional[FrozenSet[str]] = None) -> Callable[[Firewall], bool]:
    """
    Rule source matches when a source range covers the whole `source` block. A VPC rule with no
    source defaults to 0.0.0.0/0; a policy rule whose only source is a network context matches
    that whole context. `contexts`: the policy network contexts the traffic belongs to, by default
    INTERNET, or NON_INTERNET for the Google front-end ranges.
    """
    is_v4_world = source == WORLD_CIDR[V4]
    traffic = contexts or frozenset({NON_INTERNET if source in GFE_RANGES else INTERNET})

    def match(fw: Firewall) -> bool:
        if fw.network_context and fw.network_context not in traffic:
            return False
        if not fw.has_source:
            return is_v4_world or fw.network_context is not None
        return any(_contains(cidr, source) for cidr in fw.source_ranges)
    return match


def levels_open(
    levels: Iterable[Iterable[Firewall]], tags: FrozenSet[str], sas: FrozenSet[str],
    source: Callable[[Firewall], bool],
) -> PortSet:
    """Ports a chain of rule levels (in evaluation order) opens to `source` on an instance with these tags / SAs."""
    return tiered_open([
        [
            FirewallRule(fw.ports, world=source(fw), allow=fw.allow, priority=fw.priority, goto_next=fw.goto_next)
            for fw in level if applies_to(fw, tags, sas)
        ]
        for level in levels
    ])


def open_ports(
    firewalls: Iterable[Firewall], tags: FrozenSet[str], sas: FrozenSet[str],
    source: Callable[[Firewall], bool],
) -> PortSet:
    """Ports one list of ingress rules (e.g. the VPC rules alone) opens to `source`."""
    return levels_open([firewalls], tags, sas, source)


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
WITH vpc, visible, firewalls, collect(rt {{.dest_range, .priority, .tags, .next_hop_gateway}}) AS routes
OPTIONAL MATCH (vpc)-[:RESOURCE]->(pr:GCPFirewallPolicyRule)
RETURN vpc.id AS id, visible, firewalls, routes, collect(pr {{.*}}) AS policy_rules,
    vpc.network_firewall_policy_enforcement_order AS enforcement_order
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
            opened = union_all(levels_open(vpc.levels, inst.tags, inst.sas, from_cidr(s)) for s in sources)
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
    before, after = policy_levels(row.get("policy_rules") or [], row.get("enforcement_order"))
    return VpcFacts(
        visible=bool(row["visible"]) and not stale, firewalls=firewalls, routes=row["routes"],
        policies_before=before, policies_after=after,
    )


def read_vpcs(session: neo4j.Session, params: Dict) -> Dict[str, VpcFacts]:
    return {row["id"]: vpc_facts_from_row(dict(row)) for row in session.run(_VPC_QUERY, **params)}
