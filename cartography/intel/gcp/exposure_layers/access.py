"""
GCP L3: does the resource answer without credentials?

none      anonymous callers get in (allUsers / allAuthenticatedUsers on data, allUsers invoker)
required  credentials are always needed (IAM, database password, Kubernetes auth, IAP)
unknown   config cannot tell: software on instances, load balancer backends, unread IAM policy
"""
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Tuple

import neo4j

from cartography.intel.exposure.layers import AUTH_NONE
from cartography.intel.exposure.layers import auth_props
from cartography.intel.exposure.layers import AUTH_REQUIRED
from cartography.intel.exposure.layers import AUTH_UNKNOWN
from cartography.intel.gcp.exposure_layers.network import PROJECT

Verdict = Tuple[str, List[str]]

ALL_USERS = "allUsers"
ALL_AUTHENTICATED_USERS = "allAuthenticatedUsers"
PUBLIC_MEMBERS = (ALL_USERS, ALL_AUTHENTICATED_USERS)
PAP_ENFORCED = "enforced"
IAM_POLICY_RESOLVED = "resolved"
# Predefined roles that carry an invoke permission (same list as gcp_cloud_function_analysis.json).
INVOKE_ROLES = frozenset({
    "roles/cloudfunctions.admin", "roles/cloudfunctions.developer", "roles/run.admin", "roles/run.developer",
    "roles/editor", "roles/owner",
})


def _public(members: Iterable[str]) -> List[str]:
    return sorted({m for m in members if m in PUBLIC_MEMBERS})


def data_verdict(prefix: str, members: Iterable[str]) -> Verdict:
    """Data services: any public member, whatever the role, reads anonymously (or as any Google account)."""
    public = _public(members)
    if public:
        return AUTH_NONE, [f"{prefix}_{m.lower()}" for m in public]
    return AUTH_REQUIRED, ["iam"]


def bucket_auth(row: Dict) -> Verdict:
    """Public access prevention voids public grants; legacy ACLs count only without uniform access."""
    if row.get("pap") == PAP_ENFORCED:
        return AUTH_REQUIRED, ["public_access_prevention"]
    acl = [] if row.get("ubla") else row.get("acl") or []
    return data_verdict("gcs", list(row.get("members") or []) + list(acl))


def can_invoke(role: str) -> bool:
    """Unresolved custom roles (no roles/ prefix) may hold the invoke permission."""
    return role in INVOKE_ROLES or "invoke" in role.lower() or not role.startswith("roles/")


def invoker_verdict(members: Iterable[str]) -> Verdict:
    """allAuthenticatedUsers is any Google account: as anonymous as allUsers for an attacker."""
    public = _public(members)
    if public:
        return AUTH_NONE, [f"invoker_{m.lower()}" for m in public]
    return AUTH_REQUIRED, ["iam_invoker"]


def function_auth(row: Dict) -> Verdict:
    members = [
        m for b in row.get("bindings") or [] if can_invoke(str(b.get("role") or ""))
        for m in b.get("members") or []
    ]
    return invoker_verdict(members)


def cloud_run_auth(row: Dict) -> Verdict:
    """
    Reads what cloudrun.py writes (PR #507): invoker_iam_disabled, iam_policy_status
    (resolved | unresolved | not_needed) and public_invokers. Anything but a resolved policy is
    unknown: not_needed means the policy was skipped (internal ingress), not that it is closed.
    """
    if row.get("iam_disabled"):
        return AUTH_NONE, ["invoker_iam_disabled"]
    if row.get("status") != IAM_POLICY_RESOLVED:
        return AUTH_UNKNOWN, ["invoker_policy_not_read"]
    return invoker_verdict(row.get("public_invokers") or [])


def backend_service_auth(row: Dict) -> Verdict:
    # ponytail: IAP read from the backend service only; Cloud Armor and app-level auth stay unknown.
    return (AUTH_REQUIRED, ["iap"]) if row.get("iap") else (AUTH_UNKNOWN, ["backend_decides"])


def fixed(state: str, reason: str) -> Callable[[Dict], Verdict]:
    return lambda _row: (state, [reason])


def _q(label: str, returns: str = "", match_extra: str = "") -> str:
    return f"MATCH {PROJECT}-[:RESOURCE]->(n:{label}) {match_extra} RETURN n.id AS id {returns}"


RULES: Dict[str, Tuple[str, Callable[[Dict], Verdict]]] = {
    "GCPBucket": (
        _q(
            "GCPBucket",
            ", reduce(a = [], m IN collect(b.members) | a + coalesce(m, [])) AS members, "
            "n.public_acl_entities AS acl, coalesce(n.uniform_bucket_level_access, false) AS ubla, "
            "n.public_access_prevention AS pap",
            "OPTIONAL MATCH (n)-[:ATTACHED_BINDING]->(b:GCPBucketPolicyBinding)",
        ),
        bucket_auth,
    ),
    "GCPBigqueryDataset": (
        _q(
            "GCPBigqueryDataset", ", collect(a.special_group) + collect(a.iam_member) AS members",
            "OPTIONAL MATCH (a:GCPAcl)-[:APPLIES_TO]->(n)",
        ),
        lambda row: data_verdict("bigquery", row["members"]),
    ),
    "GCPFunction": (
        _q(
            "GCPFunction", ", collect(b {.role, .members}) AS bindings",
            "OPTIONAL MATCH (n)-[:ATTACHED_BINDING]->(b:GCPBinding)",
        ),
        function_auth,
    ),
    "GCPCloudRunService": (
        _q(
            "GCPCloudRunService",
            ", n.invoker_iam_disabled AS iam_disabled, n.iam_policy_status AS status, "
            "n.public_invokers AS public_invokers",
        ),
        cloud_run_auth,
    ),
    "GCPBackendService": (_q("GCPBackendService", ", coalesce(n.iap_enabled, false) AS iap"), backend_service_auth),
    "GCPSQLInstance": (_q("GCPSQLInstance"), fixed(AUTH_REQUIRED, "database_credentials")),
    "GKECluster": (_q("GKECluster"), fixed(AUTH_REQUIRED, "kubernetes_auth")),
    "GCPInstance": (_q("GCPInstance"), fixed(AUTH_UNKNOWN, "self_managed_service")),
    "GCPForwardingRule": (_q("GCPForwardingRule"), fixed(AUTH_UNKNOWN, "backend_decides")),
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
