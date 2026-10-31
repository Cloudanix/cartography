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

A path that gets through records its hops (route table, NACL, the SGs that admit its ports); a
stage that stops every port records a blocker (no internet route, NACL deny or dropped replies,
no SG admitting the world). Both are what the walk already evaluates: no per-port rule attribution.

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

from cartography.intel.exposure.layers import BLOCK_DENIED
from cartography.intel.exposure.layers import BLOCK_NO_INTERNET_ROUTE
from cartography.intel.exposure.layers import BLOCK_NOT_ALLOWED
from cartography.intel.exposure.layers import BLOCK_RETURN_PATH_DENIED
from cartography.intel.exposure.layers import hop
from cartography.intel.exposure.layers import HOP_LISTENER
from cartography.intel.exposure.layers import HOP_NACL
from cartography.intel.exposure.layers import HOP_ROUTE
from cartography.intel.exposure.layers import HOP_SECURITY_GROUP
from cartography.intel.exposure.layers import Reach
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
# internet_reachable_via of an attachment's own address: "direct_ipv4" / "direct_ipv6".
DIRECT_VIA = "direct_ip"
DIRECT_V4 = DIRECT_VIA + V4
# internet_reachable_via prefix for a path through an ELBv2: "elbv2:<lb id>".
ELBV2_VIA = "elbv2:"

# exposure_paths[].entry.type: where the internet meets the resource.
ENTRY_PUBLIC_IP = "public_ip"
ENTRY_IPV6 = "ipv6_address"
ENTRY_DNS = "dns_name"
ENTRY_ELBV2 = "elbv2"
ENTRY_FUNCTION_URL = "function_url"
ENTRY_APIGATEWAY = "apigateway"
ENTRY_CLOUDFRONT = "cloudfront"
ENTRY_SERVICE = "aws_service_endpoint"

# ELB listener protocol -> transport. GENEVE (gateway LB) carries no service port.
_LISTENER_PROTOCOLS = {
    "HTTP": "tcp", "HTTPS": "tcp", "TCP": "tcp", "TLS": "tcp", "SSL": "tcp",
    "UDP": "udp", "TCP_UDP": "all",
}


@dataclass
class SubnetFacts:
    # family -> id of the IGW the world route targets, None without one
    igw: Dict[str, Optional[str]]
    # family -> world ports the NACL passes, return path included
    nacl: Dict[str, PortSet]
    # family -> world ports the NACL inbound rules pass, replies not checked (tells deny from return path)
    nacl_inbound: Dict[str, PortSet]
    route_table: Optional[str] = None
    nacl_id: Optional[str] = None

    def hops(self, family: str) -> List[Dict]:
        """Route and NACL hops of a path entering this subnet from the internet."""
        out = [hop(HOP_ROUTE, self.route_table, f"{WORLD_CIDR[family]} -> {self.igw[family]}")]
        if self.nacl_id:
            out.append(hop(HOP_NACL, self.nacl_id))
        return out


@dataclass
class SgFacts:
    world: Dict[str, PortSet]
    any_source: PortSet
    vpc_id: Optional[str] = None
    # (ports, source SG ids, source CIDRs) per rule, for L5 internal reachability.
    rules: List[Tuple[PortSet, Set[str], List[str]]] = field(default_factory=list)


# ---------------------------------------------------------------- pure evaluation


def nacl_open(rules: List[Dict], family: str) -> Tuple[PortSet, PortSet]:
    """(inbound, outbound) world ports a subnet NACL opens, each direction on its own."""
    if not rules:
        # No NACL ingested (sync not run / denied): AWS default NACL allows everything.
        return PortSet.everything(), PortSet.everything()
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
    return inbound, outbound


def nacl_ports(rules: List[Dict], family: str) -> PortSet:
    """World-reachable inbound ports a subnet NACL passes, return path included."""
    return with_stateless_return(*nacl_open(rules, family))


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


def _admitted(
    reach: Reach, sg_ids: List[str], sgs: Dict[str, SgFacts], family: str,
    service: Optional[PortSet], sg_required: bool,
) -> PortSet:
    """Service ports some SG opens to the world; records the SGs when none does."""
    wanted = service if service is not None else PortSet.everything()
    if not sg_ids and not sg_required:
        return wanted
    admitted = firewall_ports(sg_ids, sgs, family) & wanted
    if admitted.is_empty():
        blockers: List[Optional[str]] = list(sg_ids) or [None]
        for sg_id in blockers:
            reach.block(HOP_SECURITY_GROUP, sg_id, BLOCK_NOT_ALLOWED, ports=service)
    return admitted


def _through_subnet(reach: Reach, subnet: SubnetFacts, family: str, admitted: PortSet) -> PortSet:
    """Ports `subnet` routes from the internet and lets through its NACL; records why not."""
    if not subnet.igw[family]:
        reach.block(
            HOP_ROUTE, subnet.route_table, BLOCK_NO_INTERNET_ROUTE,
            detail=f"no {WORLD_CIDR[family]} route to an internet gateway",
        )
        return PortSet.empty()
    passed = admitted & subnet.nacl[family]
    if passed.is_empty() and not admitted.is_empty():
        inbound_denied = (admitted & subnet.nacl_inbound[family]).is_empty()
        reason = BLOCK_DENIED if inbound_denied else BLOCK_RETURN_PATH_DENIED
        reach.block(HOP_NACL, subnet.nacl_id, reason, ports=admitted)
    return passed


def _subnet_gate(
    reach: Reach, subnet_ids: Iterable[str], subnets: Dict[str, SubnetFacts], family: str, admitted: PortSet,
) -> Tuple[PortSet, List[Dict]]:
    """
    Ports some subnet both routes to an IGW and passes through its NACL, with the hops of the
    subnets that pass them. Unknown subnets (not ingested for this resource type) do not
    block: we cannot see the route, so we keep the SG verdict.
    """
    known = [subnets[s] for s in subnet_ids if s in subnets]
    if not known:
        return admitted, []
    ports = PortSet.empty()
    hops: List[Dict] = []
    for subnet in known:
        passed = _through_subnet(reach, subnet, family, admitted)
        if not passed.is_empty():
            ports, hops = ports | passed, hops + subnet.hops(family)
    return ports, hops


def add_direct_path(
    reach: Reach, family: str, entry: Dict, row: Dict, subnets: Dict[str, SubnetFacts],
    sgs: Dict[str, SgFacts], service: Optional[PortSet] = None, sg_required: bool = True,
) -> PortSet:
    """
    One family's path for an attachment with its own internet address (row: subnets, sgs).
    Adds the reachable ports with their hops, or records the hops that stopped them.
    Returns the ports added.
    """
    sg_ids = list(row["sgs"])
    admitted = _admitted(reach, sg_ids, sgs, family, service, sg_required)
    ports, hops = _subnet_gate(reach, row["subnets"], subnets, family, admitted)
    hops += [
        hop(HOP_SECURITY_GROUP, s) for s in sg_ids
        if s in sgs and not (sgs[s].world[family] & ports).is_empty()
    ]
    reach.add_path(ports, DIRECT_VIA + family, hops, entry)
    return ports


def listener_ports(listeners: Iterable[Dict]) -> PortSet:
    ports = PortSet.empty()
    for listener in listeners:
        proto = _LISTENER_PROTOCOLS.get(str(listener.get("protocol") or "").upper())
        if proto and listener.get("port") is not None:
            ports = ports | PortSet.of(proto, listener["port"], listener["port"])
    return ports


def listener_hops(listeners: Iterable[Dict], ports: PortSet) -> List[Dict]:
    """Listeners serving some of `ports`; the listener itself is the deciding rule."""
    return [
        hop(HOP_LISTENER, listener.get("id"), f"{listener.get('protocol')} {listener.get('port')}")
        for listener in listeners if not (listener_ports([listener]) & ports).is_empty()
    ]


def port_set(port: Optional[int]) -> Optional[PortSet]:
    """Service port as a PortSet; None (unknown port) means "do not narrow"."""
    return PortSet.of(TCP, port, port) if port is not None else None


# ---------------------------------------------------------------- graph reads

# AWS allows one route table association per subnet, so head() picks the only one.
_SUBNET_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(s:EC2Subnet)
OPTIONAL MATCH (s)-[:HAS_EXPLICIT_ASSOCIATION|HAS_IMPLICIT_ASSOCIATION]->(:EC2RouteTableAssociation)
    <-[:HAS_ASSOCIATION]-(rtb:EC2RouteTable)
OPTIONAL MATCH (rtb)-[:MEMBER_OF_ROUTE_TABLE]->(rt:EC2Route) WHERE rt.gateway_id STARTS WITH 'igw-'
WITH s, collect(DISTINCT rtb.id) AS rtbs, collect(rt) AS igw_routes
OPTIONAL MATCH (s)<-[:PART_OF_SUBNET]-(acl:EC2NetworkAcl)
OPTIONAL MATCH (acl)<-[:MEMBER_OF_NACL]-(r:EC2NetworkAclRule)
RETURN s.subnetid AS id, head(rtbs) AS route_table,
    head([x IN igw_routes WHERE x.destination_cidr_block = '0.0.0.0/0' | x.gateway_id]) AS igw_v4,
    head([x IN igw_routes WHERE x.destination_ipv6_cidr_block = '::/0' | x.gateway_id]) AS igw_v6,
    head(collect(DISTINCT acl.id)) AS nacl_id, collect(r {{.*}}) AS nacl
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


def subnet_facts(row: Dict) -> SubnetFacts:
    opened = {f: nacl_open(row["nacl"], f) for f in (V4, V6)}
    return SubnetFacts(
        igw={V4: row["igw_v4"], V6: row["igw_v6"]},
        nacl={f: with_stateless_return(*o) for f, o in opened.items()},
        nacl_inbound={f: o[0] for f, o in opened.items()},
        route_table=row["route_table"],
        nacl_id=row["nacl_id"],
    )


def read_subnets(session: neo4j.Session, params: Dict) -> Dict[str, SubnetFacts]:
    return {row["id"]: subnet_facts(dict(row)) for row in session.run(_SUBNET_QUERY, **params)}


def read_security_groups(session: neo4j.Session, params: Dict) -> Dict[str, SgFacts]:
    return {row["id"]: sg_facts(row["rules"], row["vpc_id"]) for row in session.run(_SG_QUERY, **params)}
