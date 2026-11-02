"""
Azure L1/L2 through managed front doors that forward to private backends:

    internet -> App Gateway public listener -> gateway subnet NSG
             -> backend settings port -> backend subnet NSG + NIC NSG (source: gateway subnet)
    internet -> Azure Firewall public IP, DNAT rule with a world source
             -> translated ip:port -> backend subnet NSG + NIC NSG (source: AzureFirewallSubnet)

The gateway terminates HTTP, so it answers on its listener whatever the backends do. The
firewall answers on a DNAT port when the translated target is open or cannot be resolved
(FQDN, on-premises, another subscription), like a load balancer frontend (reach._forward).
A WAF in Prevention mode filters requests but closes no port: it is an L3 reason (access.py).
"""
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from cartography.intel.azure.exposure_layers.network import add_gated_path
from cartography.intel.azure.exposure_layers.network import Gate
from cartography.intel.azure.exposure_layers.network import gate
from cartography.intel.azure.exposure_layers.network import nsg_open_from
from cartography.intel.azure.exposure_layers.network import parse_port_range
from cartography.intel.azure.exposure_layers.network import path_hops
from cartography.intel.azure.exposure_layers.network import Results
from cartography.intel.azure.exposure_layers.network import SubnetFacts
from cartography.intel.azure.exposure_layers.network import SUBSCRIPTION
from cartography.intel.azure.exposure_layers.network import Target
from cartography.intel.exposure.layers import hop
from cartography.intel.exposure.layers import HOP_DNAT_RULE
from cartography.intel.exposure.layers import HOP_FIREWALL
from cartography.intel.exposure.layers import HOP_LISTENER
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import union_all
from cartography.intel.exposure.rules import is_world

APP_GATEWAY = "AzureApplicationGateway"
FIREWALL = "AzureFirewall"
VIA_APPGW = "appgw:"
VIA_DNAT = "azure_firewall_dnat:"
VIA_LISTENER = "public_listener"
VIA_DNAT_RULE = "dnat_rule"
REASON_FRONTEND = "public_frontend"
REASON_PUBLIC_IP = "public_ip"
SUBNETS_SEGMENT = "/subnets/"
ENTRY_APP_GATEWAY = "application_gateway"
ENTRY_FIREWALL = "azure_firewall"
# Only world-sourced DNAT rules are walked (dnat_from_world), so the source always reads Any.
DNAT_SOURCE_ANY = "Any"


@dataclass
class Backends:
    """Where a front door can send traffic, and the NSGs in front of each target."""
    by_ipconfig: Dict[str, Target]
    by_pool: Dict[str, List[Target]]
    by_ip: Dict[str, List[Tuple[Target, Set[str]]]]  # private IP -> (target, its VNet ids)
    members: Dict[Target, Tuple[List[str], List[str]]]  # target -> (subnet ids, NIC NSG ids)
    subnets: Dict[str, SubnetFacts]
    nsg_rules: Dict[str, List[Dict]]
    world_nsgs: Dict[str, PortSet]
    results: Results
    world_denies: Set[str] = field(default_factory=set)  # NSGs with a deny for internet sources


def vnets_of(subnet_ids: Iterable[str]) -> Set[str]:
    return {s.split(SUBNETS_SEGMENT)[0] for s in subnet_ids}


def nics_by_ip(nic_rows: List[Dict], label: str) -> Dict[str, List[Tuple[Target, Set[str]]]]:
    by_ip: Dict[str, List[Tuple[Target, Set[str]]]] = defaultdict(list)
    for row in nic_rows:
        for ip in row["private_ips"]:
            by_ip[ip].append(((label, row["id"]), vnets_of(row["subnets"])))
    return by_ip


def resolve_ip(ip: Optional[str], backends: Backends, near_vnets: Set[str]) -> Optional[Target]:
    """
    The NIC holding a private IP. VNets reuse addresses (10.0.0.4 is the first host of every
    default subnet), so on a clash keep the NIC in the front door's VNet; still ambiguous = None.

    ponytail: VNet peerings are not ingested, so in hub-spoke a spoke NIC whose IP also exists in
    another spoke stays unresolved. Ingest peerings to keep only peered candidates.
    """
    candidates = backends.by_ip.get(ip or "", [])
    if len(candidates) > 1:
        candidates = [c for c in candidates if c[1] & near_vnets]
    return candidates[0][0] if len(candidates) == 1 else None


def door_nsgs(backends: Backends, prefixes: List[str]) -> Dict[str, PortSet]:
    # ponytail: every NSG of the subscription is evaluated once per front door; cache by
    # prefixes if subscriptions with many gateways get slow.
    return {nsg_id: nsg_open_from(rules, prefixes) for nsg_id, rules in backends.nsg_rules.items()}


def open_backends(
    backends: Backends, nsgs_from: Dict[str, PortSet], targets: List[Target], ports: PortSet, via: str,
    hops: List[Dict], entry: Dict,
) -> bool:
    """
    Open `ports` on every target whose NSGs admit the front door's subnet. Replies stay in the
    VNet, so a backend subnet's 0.0.0.0/0 UDR (gate blind spot) does not matter on this leg.
    ponytail: a backend the NSGs close records no exposure_blocked_by entry (only direct and LB
    legs do); blame the gate here too if consoles need it.
    :return: True when a target opened, or when none is resolved (the front door still forwards).
    """
    opened = False
    for label, target_id in targets:
        subnet_ids, nsg_ids = backends.members[(label, target_id)]
        through = gate(subnet_ids, nsg_ids, backends.subnets, nsgs_from)
        passed = ports & through.ports
        if not passed.is_empty():
            backends.results[label][target_id].add_path(passed, via, [*hops, *path_hops(through)], entry)
            opened = True
    return opened or not targets


def ports_of(protocols: Optional[Iterable[Optional[str]]], specs: Iterable[Optional[str]]) -> PortSet:
    """Ports for every protocol x port spec ("443", "8000-8100"); unparseable specs add nothing."""
    ports = PortSet.empty()
    for protocol in protocols or []:
        for spec in specs:
            interval = parse_port_range(str(spec) if spec is not None else None)
            if interval:
                ports = ports | PortSet.of(protocol, *interval)
    return ports


# ---------------------------------------------------------------- Application Gateway


def appgw_targets(rule: Dict, backends: Backends, near_vnets: Set[str]) -> List[Target]:
    """Backends of one route: NIC IP configurations, VMSS pool members and private IPs."""
    ipconfigs = rule.get("backend_ip_configuration_ids") or []
    found = [backends.by_ipconfig[c] for c in ipconfigs if c in backends.by_ipconfig]
    found += backends.by_pool.get(rule.get("backend_pool_id") or "", [])
    resolved = (resolve_ip(ip, backends, near_vnets) for ip in rule.get("backend_ip_addresses") or [])
    found += [t for t in resolved if t]
    # ponytail: FQDN backends (App Service, external hosts) are not resolved.
    return sorted({t for t in found if t in backends.members})


def _listener(rule: Dict) -> PortSet:
    return ports_of([rule.get("listener_protocol")], [rule.get("listener_port")])


def _route_text(rule: Dict) -> str:
    """'https 443 -> http 8080': listener to backend settings."""
    listener = f"{str(rule.get('listener_protocol') or '').lower()} {rule.get('listener_port')}"
    backend = f"{str(rule.get('backend_protocol') or '').lower()} {rule.get('backend_port')}"
    return f"{listener} -> {backend}"


def _route(
    gw: Dict, rule: Dict, through: Gate, nsgs_from: Dict[str, PortSet], backends: Backends, reach: Reach,
    entry: Dict,
) -> None:
    """One public listener -> backend route. Backends open only when the listener itself is open."""
    hops = [hop(HOP_LISTENER, rule.get("id"), _route_text(rule))]
    if not add_gated_path(reach, _listener(rule), through, VIA_LISTENER, hops, entry):
        return
    targets = appgw_targets(rule, backends, vnets_of(gw["subnets"]))
    backend = ports_of([rule.get("backend_protocol")], [rule.get("backend_port")])
    open_backends(backends, nsgs_from, targets, backend, f"{VIA_APPGW}{gw['id']}", hops, entry)


def app_gateways(rows: List[Dict], backends: Backends) -> Dict[str, Reach]:
    """
    ponytail: v2 TCP/TLS listeners (`listeners` / `routing_rules`) and rewrite / redirect
    targets are not ingested; only HTTP(S) listeners routed to a backend pool count.
    """
    out = {}
    for row in rows:
        reach = Reach()
        if row["public"]:
            reach.public_reasons.add(REASON_FRONTEND)
        # The gateway subnet's own NSG (and UDR blind spot) decides what reaches the listener.
        through = gate(row["subnets"], [], backends.subnets, backends.world_nsgs, backends.world_denies)
        nsgs_from = door_nsgs(backends, row["prefixes"])
        routes = [r for r in row["rules"] if r.get("frontend_public")]
        # Configured public listener ports, before the gateway subnet NSG: what the gateway listens on.
        listening = union_all(_listener(r) for r in routes).to_strings()
        entry = {"type": ENTRY_APP_GATEWAY, "id": row["id"], "listener_ports": listening}
        for rule in routes:
            _route(row, rule, through, nsgs_from, backends, reach, entry)
        out[row["id"]] = reach
    return out


# ---------------------------------------------------------------- Azure Firewall DNAT


def dnat_from_world(rule: Dict, public_ips: Set[str]) -> bool:
    """
    A DNAT rule anyone on the internet can hit: world source, to this firewall's public IP.
    ponytail: IP-group sources are not resolved, so a rule sourced only from IP groups never counts.
    """
    world = any(is_world(s) for s in rule.get("source_addresses") or [])
    to_me = any(d in public_ips or is_world(d) for d in rule.get("destination_addresses") or [])
    return world and to_me


def dnat_text(rule: Dict) -> str:
    """'Any -> 20.1.2.3:2222 => 10.1.2.4:22'."""
    addresses = ",".join(rule.get("destination_addresses") or [])
    ports = ",".join(rule.get("destination_ports") or [])
    translated = f"{rule.get('translated_address')}:{rule.get('translated_port')}"
    return f"{DNAT_SOURCE_ANY} -> {addresses}:{ports} => {translated}"


def _dnat(fw: Dict, rule: Dict, nsgs_from: Dict[str, PortSet], backends: Backends, reach: Reach) -> None:
    """
    ponytail: a translated address that is an internal load balancer frontend is not followed to
    the LB backends (the firewall still counts as reachable). Resolve ILB frontend IPs if needed.
    """
    target = resolve_ip(rule.get("translated_address"), backends, vnets_of(fw["subnets"]))
    backend = ports_of(rule.get("protocols"), [rule.get("translated_port")])
    rule_hop = hop(HOP_DNAT_RULE, rule.get("id"), dnat_text(rule))
    entry = {"type": ENTRY_FIREWALL, "id": fw["id"]}
    targets = [target] if target else []
    hops = [hop(HOP_FIREWALL, fw["id"]), rule_hop]
    if open_backends(backends, nsgs_from, targets, backend, f"{VIA_DNAT}{fw['id']}", hops, entry):
        listening = ports_of(rule.get("protocols"), rule.get("destination_ports") or [])
        reach.add_path(listening, VIA_DNAT_RULE, [rule_hop], entry)


def firewalls(rows: List[Dict], backends: Backends) -> Dict[str, Reach]:
    out = {}
    for row in rows:
        reach = Reach()
        if row["public"]:
            reach.public_reasons.add(REASON_PUBLIC_IP)
        nsgs_from = door_nsgs(backends, row["prefixes"])
        public_ips = set(row["public_ips"])
        for rule in row["rules"]:
            if dnat_from_world(rule, public_ips):
                _dnat(row, rule, nsgs_from, backends, reach)
        out[row["id"]] = reach
    return out


# ---------------------------------------------------------------- graph reads

# Subnet address prefixes are the source the backend NSGs see.
_DOOR_HEAD = """
OPTIONAL MATCH (n)-[:SUBNET]->(s:AzureNetworkSubnet)
WITH n, collect(DISTINCT toLower(s.id)) AS subnets,
    reduce(acc = [], p IN collect(coalesce(s.address_prefixes, [])) | acc + p) AS prefixes
OPTIONAL MATCH (n)-[:MEMBER_PUBLIC_IP_ADDRESS]->(pip:AzurePublicIPAddress)
WITH n, subnets, prefixes, count(pip) > 0 AS public, collect(DISTINCT pip.ipAddress) AS public_ips
"""

_APPGW_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:{APP_GATEWAY})
{_DOOR_HEAD}
OPTIONAL MATCH (n)-[:HAS]->(r:AzureApplicationGatewayRule)
RETURN n.id AS id, subnets, prefixes, public, collect(r {{
    .id, .frontend_public, .listener_protocol, .listener_port, .backend_protocol, .backend_port,
    .backend_pool_id, .backend_ip_configuration_ids, .backend_ip_addresses
}}) AS rules
"""

_FIREWALL_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:{FIREWALL})
{_DOOR_HEAD}
OPTIONAL MATCH (n)-[:HAS]->(r:AzureFirewallNatRule)
RETURN n.id AS id, subnets, prefixes, public, public_ips, collect(r {{
    .id, .source_addresses, .destination_addresses, .destination_ports, .protocols,
    .translated_address, .translated_port
}}) AS rules
"""


def compute(q: Callable[[str], List[Dict]], backends: Backends) -> Results:
    """Front door results; backend NICs / VMSS in backends.results gain their paths in place."""
    return {
        APP_GATEWAY: app_gateways(q(_APPGW_QUERY), backends),
        FIREWALL: firewalls(q(_FIREWALL_QUERY), backends),
    }
