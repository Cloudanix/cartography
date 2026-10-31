"""
AWS L3: does the resource answer without credentials?

none      anonymous callers get in (public policy, auth type NONE, no Redis AUTH)
required  credentials are always needed (IAM, DB password, Kubernetes auth)
unknown   config cannot tell: self-managed software on instances, LB backends, CDN origins
"""
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple

import neo4j

from cartography.intel.aws.exposure_layers.network import ACCOUNT
from cartography.intel.exposure.layers import AUTH_NONE
from cartography.intel.exposure.layers import auth_props
from cartography.intel.exposure.layers import AUTH_REQUIRED
from cartography.intel.exposure.layers import AUTH_UNKNOWN

Verdict = Tuple[str, List[str]]


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
    "EC2Instance": (_q("EC2Instance"), fixed(AUTH_UNKNOWN, "self_managed_service")),
    "NetworkInterface": (_q("NetworkInterface"), fixed(AUTH_UNKNOWN, "self_managed_service")),
    "EMRCluster": (_q("EMRCluster"), fixed(AUTH_UNKNOWN, "self_managed_service")),
    "LoadBalancer": (_q("LoadBalancer"), fixed(AUTH_UNKNOWN, "backend_decides")),
    # ponytail: ALB authenticate-oidc/cognito listener rules not ingested; would turn some into required.
    "LoadBalancerV2": (_q("LoadBalancerV2"), fixed(AUTH_UNKNOWN, "backend_decides")),
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
