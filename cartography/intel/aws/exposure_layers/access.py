"""
AWS L3: does the resource answer without credentials?

none      anonymous callers get in (public policy, auth type NONE, no Redis AUTH)
required  credentials are always needed (IAM, DB password, Kubernetes auth, ALB authenticate action)
unknown   config cannot tell: self-managed software on instances, LB backends, CDN origins
"""
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.aws.exposure_layers.network import ACCOUNT
from cartography.intel.aws.exposure_layers.network import ELBV2_VIA
from cartography.intel.exposure.layers import AUTH_NONE
from cartography.intel.exposure.layers import auth_props
from cartography.intel.exposure.layers import AUTH_REQUIRED
from cartography.intel.exposure.layers import AUTH_UNKNOWN

Verdict = Tuple[str, List[str]]

# Listener facts from load_balancer_v2s.listener_auth_facts. A null map (no listener) is dropped by
# collect; a null flag (rules unread) reads as not authenticated, never as authenticated.
_LISTENER = "l{authenticated: coalesce(l.all_paths_authenticated, false), types: l.auth_action_types}"
# "authenticate-oidc" -> "alb_authenticate_oidc"
_ALB_REASON_PREFIX = "alb_"


def lambda_auth(row: Dict) -> Verdict:
    if row["url"] and row["url_auth"] == "NONE":
        return AUTH_NONE, ["function_url_auth_none"]
    if row["anonymous"]:
        return AUTH_NONE, ["public_resource_policy"]
    if row["url"]:
        return AUTH_REQUIRED, ["function_url_iam"]
    return AUTH_REQUIRED, ["iam_invoke"]


def apigateway_auth(row: Dict) -> Verdict:
    """Methods come from get_resources(embed=methods); None means not ingested yet."""
    if not row["policy_open"]:
        return AUTH_REQUIRED, ["resource_policy_restricts"]
    methods = row["unauthenticated"]
    if any(m for m in methods if m):
        return AUTH_NONE, ["method_authorization_none"]
    if not methods or any(m is None for m in methods):
        return AUTH_UNKNOWN, ["methods_not_ingested"]
    return AUTH_REQUIRED, ["method_authorization"]


def elasticache_auth(row: Dict) -> Verdict:
    if row["auth_token"]:
        return AUTH_REQUIRED, ["auth_token"]
    if str(row["engine"] or "").lower() == "memcached":
        return AUTH_NONE, ["memcached_no_auth"]
    # ponytail: Redis RBAC user groups live on the replication group, not ingested yet.
    return AUTH_UNKNOWN, ["no_auth_token_rbac_not_ingested"]


def alb_auth(listeners: List[Dict]) -> Optional[Verdict]:
    """
    Required when every listener authenticates every path to a target (listener_auth_facts in
    load_balancer_v2s.py); None otherwise, so callers keep their usual verdict.
    """
    if not listeners or not all(listener["authenticated"] for listener in listeners):
        return None
    types = {t for listener in listeners for t in listener["types"] or []}
    if not types:
        return None
    return AUTH_REQUIRED, sorted(_ALB_REASON_PREFIX + t.replace("-", "_") for t in types)


def load_balancer_v2_auth(row: Dict) -> Verdict:
    return alb_auth(row["listeners"]) or (AUTH_UNKNOWN, ["backend_decides"])


def instance_auth(row: Dict) -> Verdict:
    """
    Required when every internet path (internet_reachable_via, written by reach.py earlier in the
    same run) goes through an authenticating ALB; otherwise the software on the box decides.
    """
    lbs = {lb["id"]: alb_auth(lb["listeners"]) for lb in row["lbs"]}
    via = row["via"] or []
    verdicts = [lbs.get(v[len(ELBV2_VIA):]) if v.startswith(ELBV2_VIA) else None for v in via]
    if not verdicts or not all(verdicts):
        return AUTH_UNKNOWN, ["self_managed_service"]
    return AUTH_REQUIRED, sorted({reason for v in verdicts if v for reason in v[1]})


def rds_auth(row: Dict) -> Verdict:
    return AUTH_REQUIRED, ["database_credentials"] + (["iam_database_auth"] if row.get("iam_auth") else [])


def flag_auth(none_reason: str, required_reason: str) -> Callable[[Dict], Verdict]:
    """Resources where one boolean (row["open"]) decides anonymous vs credentials."""
    def verdict(row: Dict) -> Verdict:
        return (AUTH_NONE, [none_reason]) if row["open"] else (AUTH_REQUIRED, [required_reason])
    return verdict


def fixed(state: str, reason: str) -> Callable[[Dict], Verdict]:
    return lambda _row: (state, [reason])


def _q(label: str, returns: str = "", match_extra: str = "") -> str:
    return f"MATCH {ACCOUNT}-[:RESOURCE]->(n:{label}) {match_extra} RETURN n.id AS id {returns}"


# label -> (query, verdict function)
RULES: Dict[str, Tuple[str, Callable[[Dict], Verdict]]] = {
    "AWSLambda": (
        _q(
            "AWSLambda", ", n.functionurl IS NOT NULL AS url, n.functionurl_auth_type AS url_auth, "
            "coalesce(n.anonymous_access, false) AS anonymous",
        ),
        lambda_auth,
    ),
    "APIGatewayRestAPI": (
        f"""MATCH {ACCOUNT}-[:RESOURCE]->(n:APIGatewayRestAPI)
        OPTIONAL MATCH (n)-[:RESOURCE]->(r:APIGatewayResource)
        RETURN n.id AS id, coalesce(n.policy_internet_accessible, true) AS policy_open,
            collect(CASE WHEN r IS NULL THEN [] ELSE r.unauthenticated_methods END) AS unauthenticated""",
        apigateway_auth,
    ),
    "ElasticacheCluster": (
        _q("ElasticacheCluster", ", coalesce(n.auth_token_enabled, false) AS auth_token, n.engine AS engine"),
        elasticache_auth,
    ),
    "RDSInstance": (_q("RDSInstance", ", n.iam_database_authentication_enabled AS iam_auth"), rds_auth),
    "RDSCluster": (_q("RDSCluster"), fixed(AUTH_REQUIRED, "database_credentials")),
    "RedshiftCluster": (_q("RedshiftCluster"), fixed(AUTH_REQUIRED, "database_credentials")),
    "EKSCluster": (_q("EKSCluster"), fixed(AUTH_REQUIRED, "kubernetes_auth")),
    "ESDomain": (
        _q("ESDomain", ", coalesce(n.exposed_internet, false) AS open"),
        flag_auth("public_access_policy", "access_policy"),
    ),
    "S3Bucket": (
        _q("S3Bucket", ", coalesce(n.anonymous_access, false) AS open"),
        flag_auth("public_bucket_policy_or_acl", "iam"),
    ),
    "SQSQueue": (
        _q("SQSQueue", ", coalesce(n.policy_internet_accessible, false) AS open"),
        flag_auth("public_resource_policy", "iam"),
    ),
    "AWSSNSTopic": (
        _q("AWSSNSTopic", ", coalesce(n.policy_internet_accessible, false) AS open"),
        flag_auth("public_resource_policy", "iam"),
    ),
    "EBSSnapshot": (
        _q("EBSSnapshot", ", 'all' IN coalesce(n.volume_permissions, []) AS open"),
        flag_auth("shared_with_all_accounts", "iam"),
    ),
    "RDSSnapshot": (
        _q("RDSSnapshot", ", 'all' IN coalesce(n.restore_attribute_values, []) AS open"),
        flag_auth("shared_with_all_accounts", "iam"),
    ),
    "RDSClusterSnapshot": (
        _q("RDSClusterSnapshot", ", 'all' IN coalesce(n.restore_attribute_values, []) AS open"),
        flag_auth("shared_with_all_accounts", "iam"),
    ),
    "EC2Image": (
        _q("EC2Image", ", coalesce(n.ispublic, false) AS open"),
        flag_auth("public_image", "iam"),
    ),
    "EC2Instance": (
        f"""MATCH {ACCOUNT}-[:RESOURCE]->(n:EC2Instance)
        OPTIONAL MATCH (lb:LoadBalancerV2)-[:EXPOSE]->(n)
        OPTIONAL MATCH (lb)-[:ELBV2_LISTENER]->(l:ELBV2Listener)
        WITH n, lb, collect({_LISTENER}) AS listeners
        RETURN n.id AS id, n.internet_reachable_via AS via,
            collect(CASE WHEN lb IS NULL THEN null ELSE {{id: lb.id, listeners: listeners}} END) AS lbs""",
        instance_auth,
    ),
    "NetworkInterface": (_q("NetworkInterface"), fixed(AUTH_UNKNOWN, "self_managed_service")),
    "EMRCluster": (_q("EMRCluster"), fixed(AUTH_UNKNOWN, "self_managed_service")),
    "LoadBalancer": (_q("LoadBalancer"), fixed(AUTH_UNKNOWN, "backend_decides")),
    # ponytail: an LB is "required" only when all its listeners authenticate, even listeners the
    # internet cannot reach; per-listener reachability would need reach.py to keep listener ports.
    "LoadBalancerV2": (
        _q(
            "LoadBalancerV2", f", collect({_LISTENER}) AS listeners",
            "OPTIONAL MATCH (n)-[:ELBV2_LISTENER]->(l:ELBV2Listener)",
        ),
        load_balancer_v2_auth,
    ),
    "AWSCloudfrontDistribution": (_q("AWSCloudfrontDistribution"), fixed(AUTH_UNKNOWN, "origin_decides")),
}


def compute(session: neo4j.Session, params: Dict) -> Dict[str, Dict[str, Dict]]:
    """label -> node id -> L3 properties."""
    out: Dict[str, Dict[str, Dict]] = {}
    for label, (query, verdict) in RULES.items():
        out[label] = {}
        for row in session.run(query, **params):
            state, reasons = verdict(dict(row))
            out[label][row["id"]] = auth_props(state, reasons)
    return out
