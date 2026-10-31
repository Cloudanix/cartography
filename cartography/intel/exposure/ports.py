"""
Port-set algebra used by every cloud's reachability walker.

A PortSet is, per transport protocol, a sorted list of disjoint closed port intervals.
Only tcp and udp are modelled: ICMP and other IP protocols carry no port, so they never
make a service reachable in the sense the exposure layers care about.
"""
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Tuple

TCP = "tcp"
UDP = "udp"
PROTOCOLS: Tuple[str, ...] = (TCP, UDP)
MIN_PORT = 0
MAX_PORT = 65535

# Raw protocol spellings across AWS, Azure, GCP and OCI, mapped to the transports they cover.
_PROTOCOL_ALIASES: Dict[str, Tuple[str, ...]] = {
    "-1": PROTOCOLS,
    "all": PROTOCOLS,
    "*": PROTOCOLS,
    "any": PROTOCOLS,
    "tcp_udp": PROTOCOLS,
    "tcp": (TCP,),
    "6": (TCP,),
    "http": (TCP,),
    "https": (TCP,),
    "tls": (TCP,),
    "udp": (UDP,),
    "17": (UDP,),
}

Interval = Tuple[int, int]


def protocols_for(raw: Optional[str]) -> Tuple[str, ...]:
    """
    Map a provider protocol value to the transports it covers.

    :param raw: e.g. "-1", "tcp", "6", "Udp", "*", "HTTPS". None means all protocols.
    :return: subset of PROTOCOLS; empty for ICMP / GRE / ESP and other portless protocols.
    """
    if raw is None:
        return PROTOCOLS
    return _PROTOCOL_ALIASES.get(str(raw).strip().lower(), ())


def _merge(intervals: Iterable[Interval]) -> List[Interval]:
    merged: List[Interval] = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            continue
        merged.append((lo, hi))
    return merged


def _intersect(a: List[Interval], b: List[Interval]) -> List[Interval]:
    out: List[Interval] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo, hi = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def _subtract(a: List[Interval], b: List[Interval]) -> List[Interval]:
    out: List[Interval] = []
    for lo, hi in a:
        cursor = lo
        for blo, bhi in b:
            if bhi < cursor or blo > hi:
                continue
            if blo > cursor:
                out.append((cursor, blo - 1))
            cursor = bhi + 1
        if cursor <= hi:
            out.append((cursor, hi))
    return out


class PortSet:
    """Immutable per-protocol set of port intervals."""

    __slots__ = ("_by_proto",)

    def __init__(self, by_proto: Optional[Mapping[str, Iterable[Interval]]] = None):
        clean = {p: _merge(iv) for p, iv in (by_proto or {}).items() if p in PROTOCOLS}
        self._by_proto: Dict[str, List[Interval]] = {p: iv for p, iv in clean.items() if iv}

    @classmethod
    def empty(cls) -> "PortSet":
        return cls()

    @classmethod
    def everything(cls) -> "PortSet":
        return cls({p: [(MIN_PORT, MAX_PORT)] for p in PROTOCOLS})

    @classmethod
    def of(cls, protocol: Optional[str], from_port: Optional[int] = None, to_port: Optional[int] = None) -> "PortSet":
        """
        Ports a single rule covers. Missing bounds mean the whole range, as every provider
        omits them for "all ports" rules. A negative bound (AWS -1 for ICMP) also means all.
        """
        lo = MIN_PORT if from_port is None or int(from_port) < MIN_PORT else int(from_port)
        hi = MAX_PORT if to_port is None or int(to_port) < MIN_PORT else int(to_port)
        if lo > hi:
            lo, hi = hi, lo
        return cls({p: [(lo, hi)] for p in protocols_for(protocol)})

    @classmethod
    def parse(cls, values: Iterable[str]) -> "PortSet":
        """Inverse of to_strings(): ["tcp:443-443", ...]."""
        acc: Dict[str, List[Interval]] = {}
        for value in values or []:
            proto, _, rng = value.partition(":")
            lo, _, hi = rng.partition("-")
            acc.setdefault(proto, []).append((int(lo), int(hi or lo)))
        return cls(acc)

    def union(self, other: "PortSet") -> "PortSet":
        keys = set(self._by_proto) | set(other._by_proto)
        return PortSet({p: self._by_proto.get(p, []) + other._by_proto.get(p, []) for p in keys})

    def intersect(self, other: "PortSet") -> "PortSet":
        keys = set(self._by_proto) & set(other._by_proto)
        return PortSet({p: _intersect(self._by_proto[p], other._by_proto[p]) for p in keys})

    def subtract(self, other: "PortSet") -> "PortSet":
        return PortSet({p: _subtract(iv, other._by_proto.get(p, [])) for p, iv in self._by_proto.items()})

    __or__ = union
    __and__ = intersect
    __sub__ = subtract

    def is_empty(self) -> bool:
        return not self._by_proto

    def protocols(self) -> Tuple[str, ...]:
        return tuple(p for p in PROTOCOLS if p in self._by_proto)

    def to_strings(self) -> List[str]:
        """Stable "<proto>:<from>-<to>" list, the format stored on graph nodes."""
        return [f"{p}:{lo}-{hi}" for p in PROTOCOLS for lo, hi in self._by_proto.get(p, [])]

    def __eq__(self, other: object) -> bool:
        return isinstance(other, PortSet) and self._by_proto == other._by_proto

    def __repr__(self) -> str:
        return f"PortSet({self.to_strings()})"


def union_all(sets: Iterable[PortSet]) -> PortSet:
    result = PortSet.empty()
    for s in sets:
        result = result | s
    return result
