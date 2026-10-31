"""
OCI network facts for the exposure walker (docs/exposure-layers/plan.md section 4).

Path model, evaluated once per address family:
    internet -> subnet route table (0.0.0.0/0 or ::/0 -> enabled internet gateway)
             -> security lists of the subnet UNION NSGs of the VNIC / LB / endpoint -> port

OCI admits a packet when ANY security list or NSG rule on the attachment allows it, so the
rules of every list and group are pooled before evaluation. Stateful ingress rules track
replies; stateless ingress rules also need an egress rule that lets the reply leave towards
the client's ephemeral port. Only rules and routes of the packet's own family count: a
0.0.0.0/0 rule never admits an IPv6 client and ::/0 never admits an IPv4 one.

ponytail: IPv6 is evaluated for VNICs only. LB, NLB, OKE and API Gateway IPv6 addresses are
not ingested, so those stay IPv4; pass family=V6 to direct_paths once they are.
"""
import json
from dataclasses import dataclass
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional

import neo4j

from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import union_all
from cartography.intel.exposure.rules import allow_only_open
from cartography.intel.exposure.rules import FirewallRule
from cartography.intel.exposure.rules import with_stateless_return

TENANCY = (
    "(:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:OCITenancy{id: $OCI_TENANCY_ID})-[:OWNER]->"
)
# Nodes the layers write: resources of the compartment this run analyses.
COMPARTMENT = TENANCY + "(:OCICompartment{id: $OCI_COMPARTMENT_ID})-[:RESOURCE]->"
# Network objects are read tenancy-wide: a VNIC may sit in a subnet of another compartment.
_VCN = TENANCY + "(:OCICompartment)-[:RESOURCE]->(:OCIVcn)"

V4, V6 = "v4", "v6"
WORLD_CIDR = {V4: "0.0.0.0/0", V6: "::/0"}
# IPv4 vias name the gateway; IPv6 uses the cross-cloud via (AWS, GCP) so consumers can tell
# the families apart. OCI allows one internet gateway per VCN, so its id adds nothing there.
DIRECT_IPV6 = "direct_ipv6"
INTERNET_GATEWAY_PREFIX = "ocid1.internetgateway."
ROUTE_UNRESOLVED = "route_table_unresolved"
# Security list rules carry destination ports under tcp-options (protocol 6) or udp-options (17).
_SECURITY_LIST_PORT_OPTIONS = {"6": "tcp-options", "17": "udp-options"}
# NSG rule nodes flatten the same options (network.load_nsg_security_rules).
_NSG_PORT_KEYS = {"6": ("tcp_dest_port_min", "tcp_dest_port_max"), "17": ("udp_dest_port_min", "udp_dest_port_max")}
_INGRESS = "INGRESS"


@dataclass(frozen=True)
class Rule:
    """A security list or NSG rule reduced to what reachability needs."""
    ingress: bool
    peer: str  # source CIDR / NSG OCID for ingress, destination for egress
    stateless: bool
    ports: PortSet


@dataclass
class SubnetFacts:
    vcn_id: Optional[str]
    security_list_ids: List[str]
    prohibit_public_ip: bool
    # Default-route targets per family (V4 / V6); None when the route table is not in the graph.
    igw_ids: Optional[Dict[str, List[str]]]


# ---------------------------------------------------------------- pure evaluation


def _json_list(value: Any) -> List[Dict]:
    """Security list / route table rules are stored as JSON strings by network.py."""
    if isinstance(value, list):
        return value
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def security_list_rule(raw: Dict, ingress: bool) -> Rule:
    """
    One raw security list rule, e.g.
    {"protocol": "6", "source": "0.0.0.0/0", "is-stateless": false,
     "tcp-options": {"destination-port-range": {"min": 443, "max": 443}}}
    Missing port options mean every port, as in the OCI API.
    """
    protocol = str(raw.get("protocol") or "all")
    options = raw.get(_SECURITY_LIST_PORT_OPTIONS.get(protocol, "")) or {}
    port_range = options.get("destination-port-range") or {}
    return Rule(
        ingress=ingress,
        peer=raw.get("source" if ingress else "destination") or "",
        stateless=bool(raw.get("is-stateless")),
        ports=PortSet.of(protocol, port_range.get("min"), port_range.get("max")),
    )


def security_list_rules(ingress_json: Any, egress_json: Any) -> List[Rule]:
    return [security_list_rule(r, True) for r in _json_list(ingress_json)] + [
        security_list_rule(r, False) for r in _json_list(egress_json)
    ]


def nsg_rule(row: Dict) -> Rule:
    """One OCINsgSecurityRule node (properties as network.load_nsg_security_rules writes them)."""
    protocol = str(row.get("protocol") or "all")
    lo_key, hi_key = _NSG_PORT_KEYS.get(protocol, ("", ""))
    ingress = str(row.get("direction") or _INGRESS).upper() == _INGRESS
    return Rule(
        ingress=ingress,
        peer=(row.get("source") if ingress else row.get("destination")) or "",
        stateless=bool(row.get("is_stateless")),
        ports=PortSet.of(protocol, row.get(lo_key), row.get(hi_key)),
    )


def _world_open(rules: Iterable[Rule], family: str) -> PortSet:
    return allow_only_open(FirewallRule(r.ports, world=r.peer == WORLD_CIDR[family]) for r in rules)


def internet_open(rules: List[Rule], family: str = V4) -> PortSet:
    """
    Ports the pooled security lists + NSGs of one attachment open to the whole internet of
    one address family. Replies of stateless ingress may leave through any egress rule
    towards the internet of that family: stateful or stateless, either admits the packet.
    """
    inbound = [r for r in rules if r.ingress]
    stateful = _world_open((r for r in inbound if not r.stateless), family)
    stateless = _world_open((r for r in inbound if r.stateless), family)
    replies = _world_open((r for r in rules if not r.ingress), family)
    return stateful | with_stateless_return(stateless, replies)


def any_source_open(rules: List[Rule]) -> PortSet:
    """Ingress ports open to some source (used for LB -> backend hops)."""
    return union_all(r.ports for r in rules if r.ingress)


def default_route_igws(route_rules: Any, family: str = V4) -> List[str]:
    """Internet gateways the default route of one family points at (deprecated cidr-block read too)."""
    return [
        r["network-entity-id"] for r in _json_list(route_rules)
        if (r.get("destination") or r.get("cidr-block")) == WORLD_CIDR[family] and
        str(r.get("network-entity-id") or "").startswith(INTERNET_GATEWAY_PREFIX)
    ]


@dataclass
class Network:
    subnets: Dict[str, SubnetFacts]
    igw_enabled: Dict[str, bool]
    rules: Dict[str, List[Rule]]  # security list / NSG OCID -> rules

    def rules_of(self, ids: Iterable[str]) -> List[Rule]:
        return [rule for i in ids for rule in self.rules.get(i, [])]

    def attachment_rules(self, subnet_id: Optional[str], nsg_ids: Iterable[str]) -> List[Rule]:
        """Subnet security lists UNION attachment NSGs. Unresolved ids contribute nothing."""
        subnet = self.subnets.get(subnet_id or "")
        sl_ids = subnet.security_list_ids if subnet else []
        return self.rules_of(list(sl_ids) + list(nsg_ids or []))

    def internet_vias(self, subnet_id: Optional[str], family: str = V4) -> List[str]:
        """
        Entry points from the internet of one family into a subnet; empty when it has no usable
        IGW route. An unresolved subnet or route table does not block (we cannot see the route),
        the same choice the AWS walker and oci_subnet_asset_exposure make.
        """
        subnet = self.subnets.get(subnet_id or "")
        if subnet is None or subnet.igw_ids is None:
            return [ROUTE_UNRESOLVED]
        # prohibitPublicIpOnVnic is set from prohibitInternetIngress (CreateSubnetDetails), which
        # also bars internet ingress to the subnet's IPv6 addresses.
        if subnet.prohibit_public_ip:
            return []
        # Gateways missing from the graph count as enabled, like oci_subnet_asset_exposure.
        igws = [g for g in subnet.igw_ids[family] if self.igw_enabled.get(g, True)]
        if family == V6:
            return [DIRECT_IPV6] if igws else []
        return [f"igw:{g}" for g in igws]

    def direct_paths(
        self, subnet_ids: Iterable[Optional[str]], nsg_ids: Iterable[str], family: str = V4,
    ) -> Dict[str, PortSet]:
        """via -> internet-open ports, for each subnet of the attachment that routes to an IGW."""
        paths: Dict[str, PortSet] = {}
        for subnet_id in subnet_ids:
            vias = self.internet_vias(subnet_id, family)
            if not vias:
                continue
            ports = internet_open(self.attachment_rules(subnet_id, nsg_ids), family)
            for via in vias:
                paths[via] = paths.get(via, PortSet.empty()) | ports
        return paths


# ---------------------------------------------------------------- graph reads

_SUBNET_QUERY = f"""
MATCH {_VCN}-[:OCI_SUBNET]->(s:OCISubnet)
OPTIONAL MATCH (rt:OCIRouteTable{{id: s.route_table_id}})
RETURN s.id AS id, s.vcn_id AS vcn_id, coalesce(s.security_list_ids, []) AS security_list_ids,
    coalesce(s.prohibit_public_ip_on_vnic, false) AS prohibit_public_ip,
    rt IS NOT NULL AS route_known, rt.route_rules AS route_rules
"""

_IGW_QUERY = f"""
MATCH {_VCN}-[:OCI_INTERNET_GATEWAY]->(g:OCIInternetGateway)
RETURN g.id AS id, coalesce(g.is_enabled, true) AS enabled
"""

_SECURITY_LIST_QUERY = f"""
MATCH {_VCN}-[:OCI_SECURITY_LIST]->(sl:OCISecurityList)
RETURN sl.id AS id, sl.ingress_security_rules AS ingress, sl.egress_security_rules AS egress
"""

_NSG_QUERY = f"""
MATCH {_VCN}-[:OCI_NETWORK_SECURITY_GROUP]->(nsg:OCINetworkSecurityGroup)
OPTIONAL MATCH (nsg)-[:OCI_NSG_RULE]->(r:OCINsgSecurityRule)
RETURN nsg.id AS id, collect(r {{
    .direction, .protocol, .source, .destination, .is_stateless,
    .tcp_dest_port_min, .tcp_dest_port_max, .udp_dest_port_min, .udp_dest_port_max
}}) AS rules
"""

_INSTANCE_VNIC_QUERY = f"""
MATCH {COMPARTMENT}(i:OCIInstance)
OPTIONAL MATCH (i)-[:OCI_VNIC_ATTACHMENT]->(:OCIVnicAttachment)-[:OCI_VNIC]->(v:OCIVnic)
RETURN i.id AS owner, v.id AS id, v.public_ip AS public_ip, v.private_ip AS private_ip,
    coalesce(v.ipv6_addresses, []) AS ipv6_addresses, v.subnet_id AS subnet_id, coalesce(v.nsg_ids, []) AS nsg_ids
"""


def _rows(session: neo4j.Session, query: str, params: Dict) -> List[Dict]:
    return [dict(r) for r in session.run(query, **params)]


def read_network(session: neo4j.Session, params: Dict) -> Network:
    """Subnets, gateways, security lists and NSGs of the whole tenancy."""
    subnets = {
        r["id"]: SubnetFacts(
            vcn_id=r["vcn_id"],
            security_list_ids=list(r["security_list_ids"]),
            prohibit_public_ip=bool(r["prohibit_public_ip"]),
            igw_ids={f: default_route_igws(r["route_rules"], f) for f in WORLD_CIDR} if r["route_known"] else None,
        )
        for r in _rows(session, _SUBNET_QUERY, params)
    }
    rules = {
        r["id"]: security_list_rules(r["ingress"], r["egress"]) for r in _rows(session, _SECURITY_LIST_QUERY, params)
    }
    rules.update({r["id"]: [nsg_rule(x) for x in r["rules"]] for r in _rows(session, _NSG_QUERY, params)})
    igws = {r["id"]: bool(r["enabled"]) for r in _rows(session, _IGW_QUERY, params)}
    return Network(subnets=subnets, igw_enabled=igws, rules=rules)


def read_instance_vnics(session: neo4j.Session, params: Dict) -> List[Dict]:
    """One row per (instance, VNIC) of the compartment; id is None for an instance without VNICs."""
    return _rows(session, _INSTANCE_VNIC_QUERY, params)
