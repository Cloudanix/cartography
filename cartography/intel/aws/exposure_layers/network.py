"""
AWS L1 (public) + L2 (internet reachable) walker.

Path model, per IP family:
    internet -> IGW route on the subnet (0.0.0.0/0 or ::/0 -> igw-*) -> NACL (stateless, both ways)
             -> security group (world source) -> service port

Network attachments and how they enter the walk:
    NetworkInterface / EC2Instance  public IP (v4) or IPv6 address, ENI subnet + SGs
    LoadBalancerV2 / LoadBalancer   internet-facing scheme, LB subnets + SGs, listener ports
    instance behind an ELBv2        reachable LB, target port allowed by the instance SGs
    RDSInstance / RDSCluster        publicly_accessible, subnet group + SGs, endpoint port
    RedshiftCluster / EMRCluster    publicly accessible / public DNS, SGs (subnets not ingested)
    managed edges                   API Gateway, Lambda URL / triggers, EKS endpoint, CloudFront,
                                    OpenSearch public endpoint, S3 / SQS / SNS service endpoints

Blind spots (reported as reachable, never hidden): host firewalls, ports opened but not
listening, third-party appliances in the route path.
"""
from dataclasses import dataclass
from dataclasses import field
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import neo4j

from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.exposure.ports import union_all
from cartography.intel.exposure.rules import allow_only_open
from cartography.intel.exposure.rules import FirewallRule
from cartography.intel.exposure.rules import first_match_open
from cartography.intel.exposure.rules import with_stateless_return

ACCOUNT = (
    "(:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization{id: $ORGANIZATION_ID})"
    "-[:OWNER]->(:AWSAccount{id: $AWS_ID})"
)
HTTPS = PortSet.of(TCP, 443, 443)
HTTP_HTTPS = PortSet.of(TCP, 80, 80) | HTTPS
V4, V6 = "v4", "v6"
WORLD_CIDR = {V4: "0.0.0.0/0", V6: "::/0"}
# internet_reachable_via prefix for a path through an ELBv2: "elbv2:<lb id>".
ELBV2_VIA = "elbv2:"

# ELB listener protocol -> transport. GENEVE (gateway LB) carries no service port.
_LISTENER_PROTOCOLS = {
    "HTTP": "tcp", "HTTPS": "tcp", "TCP": "tcp", "TLS": "tcp", "SSL": "tcp",
    "UDP": "udp", "TCP_UDP": "all",
}


@dataclass
class SubnetFacts:
    igw: Dict[str, bool]
    nacl: Dict[str, PortSet]


@dataclass
class SgFacts:
    world: Dict[str, PortSet]
    any_source: PortSet
    vpc_id: Optional[str] = None
    # (ports, source SG ids, source CIDRs) per rule, for L5 internal reachability.
    rules: List[Tuple[PortSet, Set[str], List[str]]] = field(default_factory=list)


# ---------------------------------------------------------------- pure evaluation


def nacl_ports(rules: List[Dict], family: str) -> PortSet:
    """World-reachable inbound ports a subnet NACL passes, return path included."""
    if not rules:
        # No NACL ingested (sync not run / denied): AWS default NACL allows everything.
        return PortSet.everything()
    cidr_key = "cidr_block" if family == V4 else "ipv6_cidr_block"

    def to_rule(r: Dict) -> FirewallRule:
        return FirewallRule(
            PortSet.of(r.get("protocol"), r.get("fromport"), r.get("toport")),
            world=r.get(cidr_key) == WORLD_CIDR[family],
            allow=r.get("rule_action") == "allow",
            priority=int(r.get("rule_number") or 0),
        )
    inbound = first_match_open(to_rule(r) for r in rules if not r.get("egress"))
    outbound = first_match_open(to_rule(r) for r in rules if r.get("egress"))
    return with_stateless_return(inbound, outbound)


def sg_facts(rules: List[Dict], vpc_id: Optional[str] = None) -> SgFacts:
    """Rules as returned by _SG_QUERY: protocol, fromport, toport, cidrs, sources."""
    per_family: Dict[str, List[FirewallRule]] = {V4: [], V6: []}
    detail: List[Tuple[PortSet, Set[str], List[str]]] = []
    for r in rules:
        ports = PortSet.of(r.get("protocol"), r.get("fromport"), r.get("toport"))
        cidrs = [c for c in r.get("cidrs") or [] if c]
        for family in (V4, V6):
            world = any(c == WORLD_CIDR[family] for c in cidrs)
            per_family[family].append(FirewallRule(ports, world=world))
        detail.append((ports, set(r.get("sources") or []), cidrs))
    return SgFacts(
        world={f: allow_only_open(rs) for f, rs in per_family.items()},
        any_source=union_all(p for p, _, _ in detail),
        vpc_id=vpc_id,
        rules=detail,
    )


def firewall_ports(sg_ids: Iterable[str], sgs: Dict[str, SgFacts], family: str) -> PortSet:
    return union_all(sgs[s].world[family] for s in sg_ids if s in sgs)


def subnet_gate(subnet_ids: Iterable[str], subnets: Dict[str, SubnetFacts], family: str) -> PortSet:
    """
    Ports some subnet both routes to an IGW and passes through its NACL. Empty when no subnet
    routes to the internet. Unknown subnets (not ingested for this resource type) do not
    block: we cannot see the route, so we keep the SG verdict.
    """
    known = [subnets[s] for s in subnet_ids if s in subnets]
    if not known:
        return PortSet.everything()
    return union_all(s.nacl[family] for s in known if s.igw[family])


def direct_ports(
    family: str, has_address: bool, subnet_ids: Iterable[str], sg_ids: Iterable[str],
    subnets: Dict[str, SubnetFacts], sgs: Dict[str, SgFacts], service: Optional[PortSet] = None,
    sg_required: bool = True,
) -> PortSet:
    """One family's reachable ports for an attachment with its own internet address."""
    if not has_address:
        return PortSet.empty()
    sg_ids = list(sg_ids)
    firewall = firewall_ports(sg_ids, sgs, family) if (sg_ids or sg_required) else PortSet.everything()
    ports = firewall & subnet_gate(subnet_ids, subnets, family)
    return ports & service if service is not None else ports


def listener_ports(listeners: Iterable[Dict]) -> PortSet:
    ports = PortSet.empty()
    for listener in listeners:
        proto = _LISTENER_PROTOCOLS.get(str(listener.get("protocol") or "").upper())
        if proto and listener.get("port") is not None:
            ports = ports | PortSet.of(proto, listener["port"], listener["port"])
    return ports


def port_set(port: Optional[int]) -> Optional[PortSet]:
    """Service port as a PortSet; None (unknown port) means "do not narrow"."""
    return PortSet.of(TCP, port, port) if port is not None else None


# ---------------------------------------------------------------- graph reads

_SUBNET_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(s:EC2Subnet)
OPTIONAL MATCH (s)-[:HAS_EXPLICIT_ASSOCIATION|HAS_IMPLICIT_ASSOCIATION]->(:EC2RouteTableAssociation)
    <-[:HAS_ASSOCIATION]-(:EC2RouteTable)-[:MEMBER_OF_ROUTE_TABLE]->(rt:EC2Route)
WHERE rt.gateway_id STARTS WITH 'igw-'
WITH s, collect(rt.destination_cidr_block) AS v4, collect(rt.destination_ipv6_cidr_block) AS v6
OPTIONAL MATCH (s)<-[:PART_OF_SUBNET]-(:EC2NetworkAcl)<-[:MEMBER_OF_NACL]-(r:EC2NetworkAclRule)
RETURN s.subnetid AS id, '0.0.0.0/0' IN v4 AS igw_v4, '::/0' IN v6 AS igw_v6, collect(r {{.*}}) AS nacl
"""

# Rule ids start with the owning group id (security_groups.py), which tells the owner apart
# from SGs the rule references as a source: both use MEMBER_OF_EC2_SECURITY_GROUP.
_SG_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(sg:EC2SecurityGroup)
OPTIONAL MATCH (vpc:AWSVpc)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
OPTIONAL MATCH (sg)<-[:MEMBER_OF_EC2_SECURITY_GROUP]-(rule:IpPermissionInbound)
WHERE rule.ruleid STARTS WITH sg.id + '/'
OPTIONAL MATCH (rng)-[:MEMBER_OF_IP_RULE]->(rule) WHERE rng:IpRange OR rng:Ipv6Range
OPTIONAL MATCH (rule)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(src:EC2SecurityGroup) WHERE src.id <> sg.id
WITH sg, vpc, rule, collect(DISTINCT rng.range) AS cidrs, collect(DISTINCT src.id) AS sources
RETURN sg.id AS id, vpc.id AS vpc_id, collect(CASE WHEN rule IS NULL THEN null ELSE
    {{protocol: rule.protocol, fromport: rule.fromport, toport: rule.toport, cidrs: cidrs, sources: sources}}
END) AS rules
"""


def read_subnets(session: neo4j.Session, params: Dict) -> Dict[str, SubnetFacts]:
    facts = {}
    for row in session.run(_SUBNET_QUERY, **params):
        facts[row["id"]] = SubnetFacts(
            igw={V4: row["igw_v4"], V6: row["igw_v6"]},
            nacl={f: nacl_ports(row["nacl"], f) for f in (V4, V6)},
        )
    return facts


def read_security_groups(session: neo4j.Session, params: Dict) -> Dict[str, SgFacts]:
    return {row["id"]: sg_facts(row["rules"], row["vpc_id"]) for row in session.run(_SG_QUERY, **params)}
