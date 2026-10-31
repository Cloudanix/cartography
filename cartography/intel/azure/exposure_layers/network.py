"""
Azure L2 building blocks: NSG evaluation and the gate every inbound compute path crosses.

    internet -> public IP on a NIC | LB public frontend + rule / NAT rule
             -> subnet NSG -> NIC NSG -> port

Both NSG levels must allow (intersection); a level without an NSG allows everything.
Standard SKU public IPs and load balancers are closed by default: with no NSG at either
level nothing gets in. A missing SKU (not ingested yet) counts as Basic (open, upper bound).
NSG rules run first-match by priority. Default rules are not ingested; for internet
sources the only one that decides is DenyAllInBound (65500), so "no matching rule" = deny.

A subnet whose 0.0.0.0/0 user-defined route points anywhere but Internet (NVA, VPN gateway,
None) routes replies through that hop, which decides what survives. That is a blind spot:
the path is reported as `unknown:udr_default_route_<hop>` in internet_reachable_via and
never as reachable.
"""
from dataclasses import dataclass
from dataclasses import field
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import MAX_PORT
from cartography.intel.exposure.ports import MIN_PORT
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import union_all
from cartography.intel.exposure.rules import FirewallRule
from cartography.intel.exposure.rules import first_match_open
from cartography.intel.exposure.rules import is_world

SUBSCRIPTION = (
    "(:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AzureTenant{id: $AZURE_TENANT_ID})"
    "-[:RESOURCE]->(:AzureSubscription{id: $AZURE_SUBSCRIPTION_ID})"
)
ANY_PORT = "*"
INBOUND = "inbound"
ALLOW = "allow"
INTERNET_HOP = "internet"
DEFAULT_ROUTE = "0.0.0.0/0"
UNKNOWN_UDR_VIA = "unknown:udr_default_route_"
STANDARD_SKU = "standard"
# Destinations that cover every NIC behind the NSG.
_ANY_DESTINATIONS = frozenset({"", "*", "any", "virtualnetwork", "0.0.0.0/0", "::/0"})


@dataclass
class Gate:
    """What survives subnet NSG + NIC NSG, and why the verdict may be unknown."""
    ports: PortSet
    blind: List[str] = field(default_factory=list)
    has_nsg: bool = False


def for_sku(through: Gate, skus: Iterable[Optional[str]]) -> Gate:
    """A Standard SKU front door admits nothing unless some NSG on the path allows it."""
    if through.has_nsg or not any(str(s or "").lower() == STANDARD_SKU for s in skus):
        return through
    return Gate(PortSet.empty(), through.blind, has_nsg=False)


# ---------------------------------------------------------------- pure evaluation


def parse_port_range(value: Optional[str]) -> Optional[Tuple[int, int]]:
    """
    NSG port spec to an interval: "443", "1000-2000", "*". None when unparseable.

    >>> parse_port_range("1000-2000")
    (1000, 2000)
    """
    text = str(value or "").strip()
    if text == ANY_PORT:
        return MIN_PORT, MAX_PORT
    lo, _, hi = text.partition("-")
    try:
        return int(lo), int(hi or lo)
    except ValueError:
        return None


def rule_ports(rule: Dict) -> PortSet:
    """Destination ports of an NSG rule (single range and list), for its protocol."""
    specs = [rule.get("destination_port_range")] + list(rule.get("destination_port_ranges") or [])
    specs = [s for s in specs if s not in (None, "")] or [ANY_PORT]
    ports = PortSet.empty()
    for spec in specs:
        interval = parse_port_range(spec)
        if interval:
            ports = ports | PortSet.of(rule.get("protocol"), *interval)
    return ports


def rule_is_world(rule: Dict) -> bool:
    sources = [rule.get("source_address_prefix")] + list(rule.get("source_address_prefixes") or [])
    return any(is_world(s) for s in sources)


def nsg_open(rules: Iterable[Dict]) -> PortSet:
    """
    Ports one NSG opens to the whole internet.

    ponytail: destination prefixes are not matched to each NIC's IP. A deny scoped to one
    destination is skipped and an allow scoped to one opens every NIC behind the NSG, so
    the result is an upper bound. Match destination CIDRs per NIC if this over-reports.
    """
    evaluated = []
    for rule in rules:
        if str(rule.get("direction") or "").lower() != INBOUND:
            continue
        allow = str(rule.get("access") or "").lower() == ALLOW
        destination = str(rule.get("destination_address_prefix") or "").strip().lower()
        if not allow and destination not in _ANY_DESTINATIONS:
            continue
        evaluated.append(
            FirewallRule(
                rule_ports(rule), world=rule_is_world(rule), allow=allow, priority=int(rule.get("priority") or 0),
            ),
        )
    return first_match_open(evaluated)


def blind_hops(default_route_hops: Iterable[Optional[str]]) -> List[str]:
    """Via markers for 0.0.0.0/0 UDRs that do not go straight to the internet."""
    return sorted({
        f"{UNKNOWN_UDR_VIA}{str(hop).lower()}" for hop in default_route_hops
        if hop and str(hop).lower() != INTERNET_HOP
    })


def nsg_gate(nsg_ids: Iterable[str], nsgs: Dict[str, PortSet]) -> PortSet:
    """Every known NSG must allow; no NSG (or one outside this subscription) allows all."""
    ports = PortSet.everything()
    for nsg_id in nsg_ids:
        if nsg_id in nsgs:
            ports = ports & nsgs[nsg_id]
    return ports


@dataclass
class SubnetFacts:
    nsg_ids: List[str]
    blind: List[str]


def gate(
    subnet_ids: Iterable[str], nic_nsg_ids: Iterable[str],
    subnets: Dict[str, SubnetFacts], nsgs: Dict[str, PortSet],
) -> Gate:
    """
    Subnet NSG AND NIC NSG. Unknown subnets do not block (we cannot see their NSG).
    ponytail: a NIC spanning several subnets gets the union of their verdicts.
    """
    known = [subnets[s] for s in subnet_ids if s in subnets]
    subnet_ports = union_all(nsg_gate(s.nsg_ids, nsgs) for s in known) if known else PortSet.everything()
    blind = sorted({b for s in known for b in s.blind})
    nic_nsg_ids = list(nic_nsg_ids)
    has_nsg = bool(nic_nsg_ids) or any(s.nsg_ids for s in known)
    return Gate(subnet_ports & nsg_gate(nic_nsg_ids, nsgs), blind, has_nsg)


def add_gated_path(reach: Reach, ports: PortSet, through: Gate, via: str) -> bool:
    """
    Add `ports` that pass `through` to `reach`. A path the NSGs close stays closed even
    behind an NVA; an open one behind an NVA becomes an unknown marker, not a port.
    :return: True when ports were added (the path is definitely open).
    """
    passed = ports & through.ports
    if passed.is_empty():
        return False
    if through.blind:
        reach.via.update(through.blind)
        return False
    reach.add_path(passed, via)
    return True


# ---------------------------------------------------------------- graph reads

_NSG_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(g:AzureNetworkSecurityGroup)
OPTIONAL MATCH (g)-[:CONTAIN]->(r:AzureNetworkSecurityRule)
RETURN toLower(g.id) AS id, collect(r {{
    .direction, .access, .priority, .protocol, .source_address_prefix, .source_address_prefixes,
    .destination_port_range, .destination_port_ranges, .destination_address_prefix
}}) AS rules
"""

_SUBNET_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(:AzureNetwork)-[:CONTAIN]->(s:AzureNetworkSubnet)
OPTIONAL MATCH (s)-[:MEMBER_NETWORK_SECURITY_GROUP]->(g:AzureNetworkSecurityGroup)
OPTIONAL MATCH (s)-[:CONTAIN]->(:AzureRouteTable)-[:CONTAIN]->(rt:AzureNetworkRoute)
WHERE rt.address_prefix = '{DEFAULT_ROUTE}'
RETURN toLower(s.id) AS id, collect(DISTINCT toLower(g.id)) AS nsgs, collect(DISTINCT rt.next_hop_type) AS hops
"""


def read_nsgs(session: neo4j.Session, params: Dict) -> Dict[str, PortSet]:
    """Lowercased NSG id -> ports it opens to the internet."""
    return {row["id"]: nsg_open(row["rules"]) for row in session.run(_NSG_QUERY, **params)}


def read_subnets(session: neo4j.Session, params: Dict) -> Dict[str, SubnetFacts]:
    """Lowercased subnet id -> its NSGs and default-route blind spots."""
    return {
        row["id"]: SubnetFacts(nsg_ids=row["nsgs"], blind=blind_hops(row["hops"]))
        for row in session.run(_SUBNET_QUERY, **params)
    }
