"""
AWS L1 + L2 per resource type. Each reader returns {node_id: Reach} for EVERY node of its
label in the account, so a node that stopped being reachable is rewritten with false.
"""
from typing import Dict
from typing import List

import neo4j

from cartography.intel.aws.exposure_layers.network import ACCOUNT
from cartography.intel.aws.exposure_layers.network import direct_ports
from cartography.intel.aws.exposure_layers.network import ELBV2_VIA
from cartography.intel.aws.exposure_layers.network import HTTP_HTTPS
from cartography.intel.aws.exposure_layers.network import HTTPS
from cartography.intel.aws.exposure_layers.network import listener_ports
from cartography.intel.aws.exposure_layers.network import port_set
from cartography.intel.aws.exposure_layers.network import read_security_groups
from cartography.intel.aws.exposure_layers.network import read_subnets
from cartography.intel.aws.exposure_layers.network import SgFacts
from cartography.intel.aws.exposure_layers.network import SubnetFacts
from cartography.intel.aws.exposure_layers.network import V4
from cartography.intel.aws.exposure_layers.network import V6
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import union_all
from cartography.intel.exposure.rules import is_world

Results = Dict[str, Dict[str, Reach]]  # label -> node id -> Reach


def _rows(session: neo4j.Session, query: str, params: Dict) -> List[Dict]:
    return [dict(r) for r in session.run(query, **params)]


def _address_reach(
    row: Dict, subnets: Dict[str, SubnetFacts], sgs: Dict[str, SgFacts],
) -> Reach:
    """Shared by ENIs and instances: rows carry public_ips, ipv6, subnets, sgs."""
    reach = Reach()
    has = {V4: bool(row.get("public_ips")), V6: bool(row.get("ipv6"))}
    if has[V4]:
        reach.public_reasons.add("public_ip")
    if has[V6]:
        reach.public_reasons.add("ipv6_address")
    for family in (V4, V6):
        ports = direct_ports(family, has[family], row["subnets"], row["sgs"], subnets, sgs)
        reach.add_path(ports, f"direct_ip{family}")
    return reach


_ENI_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(eni:NetworkInterface)
OPTIONAL MATCH (eni)-[:PART_OF_SUBNET]->(s:EC2Subnet)
OPTIONAL MATCH (eni)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
OPTIONAL MATCH (eni)-[:PRIVATE_IP_ADDRESS]->(pip:EC2PrivateIp)
WITH eni, collect(DISTINCT s.subnetid) AS subnets, collect(DISTINCT sg.id) AS sgs,
    collect(DISTINCT pip.public_ip) AS pip_ips
RETURN eni.id AS id, subnets, sgs, [ip IN pip_ips + [eni.public_ip] WHERE ip IS NOT NULL] AS public_ips,
    coalesce(eni.ipv6_addresses, []) AS ipv6
"""

# ponytail: one instance = union of its ENIs' subnets/SGs/addresses; multi-ENI instances with
# different SGs per ENI are over-approximated. Per-ENI truth is on the NetworkInterface nodes.
_INSTANCE_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(i:EC2Instance)
OPTIONAL MATCH (i)-[:NETWORK_INTERFACE]->(eni:NetworkInterface)
OPTIONAL MATCH (eni)-[:PART_OF_SUBNET]->(es:EC2Subnet)
OPTIONAL MATCH (eni)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(esg:EC2SecurityGroup)
OPTIONAL MATCH (i)-[:PART_OF_SUBNET]->(s:EC2Subnet)
OPTIONAL MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
WITH i, collect(DISTINCT es.subnetid) + collect(DISTINCT s.subnetid) AS subnets,
    collect(DISTINCT esg.id) + collect(DISTINCT sg.id) AS sgs,
    collect(DISTINCT eni.public_ip) AS eni_ips, reduce(a = [], x IN collect(eni.ipv6_addresses) | a + x) AS ipv6
RETURN i.id AS id, subnets, sgs, [ip IN eni_ips + [i.publicipaddress] WHERE ip IS NOT NULL] AS public_ips, ipv6
"""


def addresses(rows: List[Dict], subnets: Dict, sgs: Dict) -> Dict[str, Reach]:
    """ENIs and instances: reachable through their own public / IPv6 addresses."""
    return {r["id"]: _address_reach(r, subnets, sgs) for r in rows}


_LBV2_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(lb:LoadBalancerV2)
OPTIONAL MATCH (lb)-[:SUBNET]->(s:EC2Subnet)
OPTIONAL MATCH (lb)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
OPTIONAL MATCH (lb)-[:ELBV2_LISTENER]->(l:ELBV2Listener)
RETURN lb.id AS id, lb.scheme AS scheme, lb.type AS type, coalesce(lb.target_group_arns, []) AS target_groups,
    collect(DISTINCT s.subnetid) AS subnets, collect(DISTINCT sg.id) AS sgs,
    collect(DISTINCT CASE WHEN l IS NULL THEN null ELSE {{port: l.port, protocol: l.protocol}} END) AS listeners
"""

_ELB_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(lb:LoadBalancer)
OPTIONAL MATCH (lb)-[:SUBNET]->(s:EC2Subnet)
OPTIONAL MATCH (lb)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
OPTIONAL MATCH (lb)-[:ELB_LISTENER]->(l:ELBListener)
RETURN lb.id AS id, lb.scheme AS scheme, 'classic' AS type, [] AS target_groups,
    collect(DISTINCT s.subnetid) AS subnets, collect(DISTINCT sg.id) AS sgs,
    collect(DISTINCT CASE WHEN l IS NULL THEN null ELSE {{port: l.port, protocol: l.protocol}} END) AS listeners
"""


def load_balancers(rows: List[Dict], subnets: Dict, sgs: Dict) -> Dict[str, Reach]:
    out = {}
    for row in rows:
        reach = Reach()
        public = row.get("scheme") == "internet-facing"
        if public:
            reach.public_reasons.add("internet_facing_scheme")
        ports = direct_ports(
            V4, public, row["subnets"], row["sgs"], subnets, sgs,
            service=listener_ports(row["listeners"]),
            # NLBs created before Aug 2023 have no security group and forward from anywhere.
            sg_required=row.get("type") != "network",
        )
        reach.add_path(ports, "direct_ipv4")
        out[row["id"]] = reach
    return out


_LB_TARGET_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(lb:LoadBalancerV2)-[e:EXPOSE]->(i:EC2Instance)
OPTIONAL MATCH (i)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
OPTIONAL MATCH (i)-[:NETWORK_INTERFACE]->(:NetworkInterface)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(esg:EC2SecurityGroup)
RETURN lb.id AS lb, i.id AS instance, e.port AS port, e.protocol AS protocol,
    collect(DISTINCT sg.id) + collect(DISTINCT esg.id) AS sgs
"""


def add_lb_targets(
    rows: List[Dict], lbs: Dict[str, Reach], instance_reach: Dict[str, Reach], sgs: Dict[str, SgFacts],
) -> None:
    """
    An instance behind a reachable ELBv2 is reachable on its target port when its SGs admit
    that port. ponytail: any source counts, not only the LB's SG or subnet CIDRs.
    """
    for row in rows:
        lb = lbs.get(row["lb"])
        if lb is None or lb.ports.is_empty() or row["instance"] not in instance_reach:
            continue
        proto = "udp" if str(row.get("protocol") or "").upper() == "UDP" else "tcp"
        target = port_set(row.get("port")) if proto == "tcp" else PortSet.of("udp", row["port"], row["port"])
        allowed = union_all(sgs[s].any_source for s in row["sgs"] if s in sgs)
        instance_reach[row["instance"]].add_path((target or PortSet.everything()) & allowed, ELBV2_VIA + row["lb"])


_RDS_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(rds:RDSInstance)
OPTIONAL MATCH (rds)-[:MEMBER_OF_DB_SUBNET_GROUP]->(:DBSubnetGroup)-[:CONNECTED_TO]->(s:EC2Subnet)
OPTIONAL MATCH (rds)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
OPTIONAL MATCH (rds)-[:IS_CLUSTER_MEMBER_OF]->(c:RDSCluster)
RETURN rds.id AS id, rds.publicly_accessible AS public, rds.endpoint_port AS port, c.id AS cluster,
    collect(DISTINCT s.subnetid) AS subnets, collect(DISTINCT sg.id) AS sgs
"""

_RDS_CLUSTER_QUERY = f"MATCH {ACCOUNT}-[:RESOURCE]->(c:RDSCluster) RETURN c.id AS id"

_REDSHIFT_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(c:RedshiftCluster)
OPTIONAL MATCH (c)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
RETURN c.id AS id, c.publicly_accessible AS public, c.endpoint_port AS port, [] AS subnets,
    collect(DISTINCT sg.id) AS sgs
"""

_EMR_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(c:EMRCluster)
RETURN c.id AS id, c.master_public_dns_name IS NOT NULL AS public, null AS port, [] AS subnets,
    coalesce(c.master_security_group_ids, []) AS sgs
"""


def databases(rows: List[Dict], subnets: Dict, sgs: Dict, reason: str) -> Dict[str, Reach]:
    """Endpoint services with a public flag, SGs and one port (RDS, Redshift, EMR master)."""
    out = {}
    for row in rows:
        reach = Reach()
        public = bool(row.get("public"))
        if public:
            reach.public_reasons.add(reason)
        ports = direct_ports(V4, public, row["subnets"], row["sgs"], subnets, sgs, service=port_set(row.get("port")))
        reach.add_path(ports, "direct_ipv4")
        out[row["id"]] = reach
    return out


def rds_clusters(cluster_ids: List[str], rds_rows: List[Dict], rds: Dict[str, Reach]) -> Dict[str, Reach]:
    """A cluster endpoint resolves to its members: reachable when a member is."""
    out = {cid: Reach() for cid in cluster_ids}
    for row in rds_rows:
        cluster = out.get(row.get("cluster") or "")
        if cluster is None:
            continue
        member = rds[row["id"]]
        cluster.public_reasons |= member.public_reasons
        cluster.add_path(member.ports, f"member:{row['id']}")
    return out


def _flagged(rows: List[Dict], ports: PortSet, via: str, reason: str) -> Dict[str, Reach]:
    """Managed edge services: reachable on fixed ports when the row's flag is set."""
    out = {}
    for row in rows:
        reach = Reach()
        if row.get("public"):
            reach.public_reasons.add(reason)
            reach.add_path(ports, via)
        out[row["id"]] = reach
    return out


_APIGW_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(api:APIGatewayRestAPI)
WITH api, coalesce(api.endpoint_conf_types, []) AS types
RETURN api.id AS id,
    ('REGIONAL' IN types OR 'EDGE' IN types)
    AND (NOT coalesce(api.disableexecuteapiendpoint, false) OR api.public_custom_domains IS NULL
         OR size(api.public_custom_domains) > 0) AS public
"""

_EKS_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(c:EKSCluster)
RETURN c.id AS id, coalesce(c.endpoint_public_access, false) AS endpoint_public,
    coalesce(c.public_access_cidrs, []) AS cidrs
"""

_CLOUDFRONT_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(d:AWSCloudfrontDistribution) RETURN d.id AS id, coalesce(d.enabled, false) AS public
"""

# Domains inside a VPC report no public Endpoint, only VPC endpoints.
_ES_QUERY = f"MATCH {ACCOUNT}-[:RESOURCE]->(es:ESDomain) RETURN es.id AS id, es.endpoint IS NOT NULL AS public"

# S3 / SQS / SNS always answer on the regional service endpoint; the resource policy (L3)
# decides who gets in, so the L1 reason records a public policy, not an address.
_S3_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(b:S3Bucket) RETURN b.id AS id, coalesce(b.anonymous_access, false) AS policy_public
"""
_SQS_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(q:SQSQueue)
RETURN q.id AS id, coalesce(q.policy_internet_accessible, false) AS policy_public
"""
_SNS_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(t:AWSSNSTopic)
RETURN t.id AS id, coalesce(t.policy_internet_accessible, false) AS policy_public
"""

_ELASTICACHE_QUERY = f"MATCH {ACCOUNT}-[:RESOURCE]->(c:ElasticacheCluster) RETURN c.id AS id"


def eks_clusters(rows: List[Dict]) -> Dict[str, Reach]:
    out = {}
    for row in rows:
        reach = Reach()
        if row["endpoint_public"]:
            reach.public_reasons.add("public_endpoint")
            if not row["cidrs"] or any(is_world(c) for c in row["cidrs"]):
                reach.add_path(HTTPS, "public_endpoint")
        out[row["id"]] = reach
    return out


def service_endpoints(rows: List[Dict]) -> Dict[str, Reach]:
    out = {}
    for row in rows:
        reach = Reach()
        if row["policy_public"]:
            reach.public_reasons.add("public_resource_policy")
        reach.add_path(HTTPS, "aws_service_endpoint")
        out[row["id"]] = reach
    return out


_LAMBDA_QUERY = f"""
MATCH {ACCOUNT}-[:RESOURCE]->(lf:AWSLambda)
RETURN lf.id AS id, lf.functionurl IS NOT NULL AS url, coalesce(lf.public_trigger_sources, []) AS triggers,
    coalesce(lf.apigateway_source_api_ids, []) AS apis, coalesce(lf.alb_source_target_group_arns, []) AS tgs
"""


def lambdas(rows: List[Dict], apis: Dict[str, Reach], lb_rows: List[Dict], lbs: Dict[str, Reach]) -> Dict[str, Reach]:
    """
    Function URL, or an internet-facing trigger. An unresolved trigger source (API / target
    group not in this account's graph) counts as reachable, as the existing exposure job does.
    """
    tg_to_lb = {tg: row["id"] for row in lb_rows for tg in row["target_groups"]}
    out = {}
    for row in rows:
        reach = Reach()
        if row["url"]:
            reach.public_reasons.add("function_url")
            reach.add_path(HTTPS, "function_url")
        if "apigateway" in row["triggers"]:
            if not row["apis"] or any(a not in apis or not apis[a].ports.is_empty() for a in row["apis"]):
                reach.add_path(HTTPS, "apigateway_trigger")
        if "cloudfront" in row["triggers"]:
            reach.add_path(HTTPS, "cloudfront_trigger")
        if "alb" in row["triggers"]:
            _add_alb_trigger(reach, row["tgs"], tg_to_lb, lbs)
        out[row["id"]] = reach
    return out


def _add_alb_trigger(reach: Reach, tgs: List[str], tg_to_lb: Dict[str, str], lbs: Dict[str, Reach]) -> None:
    if not tgs or any(tg not in tg_to_lb for tg in tgs):
        reach.add_path(HTTPS, "alb_trigger")
    for tg in tgs:
        lb_id = tg_to_lb.get(tg)
        if lb_id and lb_id in lbs:
            reach.add_path(lbs[lb_id].ports, ELBV2_VIA + lb_id)


def compute(session: neo4j.Session, params: Dict) -> Results:
    """All AWS L1/L2 results for one account."""
    subnets = read_subnets(session, params)
    sgs = read_security_groups(session, params)

    def q(query: str) -> List[Dict]:
        return _rows(session, query, params)

    lbv2_rows = q(_LBV2_QUERY)
    lbv2 = load_balancers(lbv2_rows, subnets, sgs)
    inst = addresses(q(_INSTANCE_QUERY), subnets, sgs)
    add_lb_targets(q(_LB_TARGET_QUERY), lbv2, inst, sgs)
    rds_rows = q(_RDS_QUERY)
    rds = databases(rds_rows, subnets, sgs, "publicly_accessible")
    apis = _flagged(q(_APIGW_QUERY), HTTPS, "apigateway_endpoint", "public_endpoint")
    results: Results = {
        "NetworkInterface": addresses(q(_ENI_QUERY), subnets, sgs),
        "EC2Instance": inst,
        "LoadBalancerV2": lbv2,
        "LoadBalancer": load_balancers(q(_ELB_QUERY), subnets, sgs),
        "RDSInstance": rds,
        "RDSCluster": rds_clusters([r["id"] for r in q(_RDS_CLUSTER_QUERY)], rds_rows, rds),
        "RedshiftCluster": databases(q(_REDSHIFT_QUERY), subnets, sgs, "publicly_accessible"),
        "EMRCluster": databases(q(_EMR_QUERY), subnets, sgs, "master_public_dns"),
        "ElasticacheCluster": {r["id"]: Reach() for r in q(_ELASTICACHE_QUERY)},
        "APIGatewayRestAPI": apis,
        "AWSLambda": lambdas(q(_LAMBDA_QUERY), apis, lbv2_rows, lbv2),
        "EKSCluster": eks_clusters(q(_EKS_QUERY)),
        "AWSCloudfrontDistribution": _flagged(q(_CLOUDFRONT_QUERY), HTTP_HTTPS, "cloudfront", "enabled_distribution"),
        "ESDomain": _flagged(q(_ES_QUERY), HTTPS, "public_endpoint", "public_endpoint"),
        "S3Bucket": service_endpoints(q(_S3_QUERY)),
        "SQSQueue": service_endpoints(q(_SQS_QUERY)),
        "AWSSNSTopic": service_endpoints(q(_SNS_QUERY)),
    }
    return results
