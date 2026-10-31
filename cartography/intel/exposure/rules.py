"""
Firewall evaluation shared by the cloud walkers.

Two rule models cover every provider:
- allow-only (stateful allow lists): AWS security groups, OCI security lists and NSGs.
- first-match (ordered allow/deny): AWS NACLs, Azure NSGs, GCP firewall rules and policies.

"Internet" means the whole internet: only rules whose source is a world CIDR or tag count.
A rule admitting 203.0.113.0/24 opens a port to someone on the internet, not to everyone,
and a deny for that /24 does not close it for everyone either.
"""
from dataclasses import dataclass
from typing import Iterable
from typing import Optional

from cartography.intel.exposure.ports import PortSet

# Source values meaning "anywhere": CIDRs plus Azure service tags / wildcard spellings.
WORLD_SOURCES = frozenset({"0.0.0.0/0", "::/0", "*", "any", "internet"})

# Reply traffic of an inbound connection leaves on the client's ephemeral port. Stateless
# filters (AWS NACL, OCI stateless rules) must open these outbound or the connection dies.
# ponytail: IANA + Linux ranges folded into one band; exact client OS range is unknowable.
EPHEMERAL_PORTS = PortSet.of("all", 1024, 65535)


def is_world(source: Optional[str]) -> bool:
    return source is not None and str(source).strip().lower() in WORLD_SOURCES


@dataclass(frozen=True)
class FirewallRule:
    """One provider rule reduced to what reachability needs."""
    ports: PortSet
    world: bool
    allow: bool = True
    priority: int = 0


def allow_only_open(rules: Iterable[FirewallRule]) -> PortSet:
    """Ports a stateful allow-list opens to the whole internet."""
    opened = PortSet.empty()
    for rule in rules:
        if rule.world and rule.allow:
            opened = opened | rule.ports
    return opened


def first_match_open(rules: Iterable[FirewallRule], default_allow: bool = False) -> PortSet:
    """
    Ports an ordered allow/deny list opens to the whole internet.

    Rules run by ascending priority; on a tie deny runs first (GCP semantics, harmless
    elsewhere since AWS and Azure priorities are unique). Each port is decided by the first
    world rule covering it. Ports no rule decides fall to default_allow.
    """
    undecided = PortSet.everything()
    opened = PortSet.empty()
    for rule in sorted(rules, key=lambda r: (r.priority, r.allow)):
        if not rule.world:
            continue
        decided = rule.ports & undecided
        if rule.allow:
            opened = opened | decided
        undecided = undecided - decided
    return opened | undecided if default_allow else opened


def with_stateless_return(inbound: PortSet, outbound_open: PortSet) -> PortSet:
    """Drop inbound protocols whose replies a stateless outbound filter blocks."""
    replies = outbound_open & EPHEMERAL_PORTS
    return PortSet({p: [(0, 65535)] for p in replies.protocols()}) & inbound
