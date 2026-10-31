"""
OCI L3: does the resource answer without credentials?

none      anonymous callers get in (public bucket / repository, anonymous API deployment)
required  credentials are always needed (IAM, database credentials, Kubernetes auth)
unknown   config cannot tell: self-managed software on instances, LB backends
"""
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple

import neo4j

from cartography.intel.exposure.layers import AUTH_NONE
from cartography.intel.exposure.layers import auth_props
from cartography.intel.exposure.layers import AUTH_REQUIRED
from cartography.intel.exposure.layers import AUTH_UNKNOWN
from cartography.intel.oci.exposure_layers.network import COMPARTMENT
from cartography.intel.oci.exposure_layers.reach import PUBLIC_BUCKET_ACCESS_TYPES
from cartography.intel.oci.load_balancer import LOAD_BALANCER_LABEL
from cartography.intel.oci.load_balancer import NETWORK_LOAD_BALANCER_LABEL

Verdict = Tuple[str, List[str]]
DATABASE_CREDENTIALS = "database_credentials"


def api_gateway_auth(row: Dict) -> Verdict:
    """deployments is None when api_gateway.py could not list them (or ran before they were ingested)."""
    deployments = row["deployments"]
    if deployments is None:
        return AUTH_UNKNOWN, ["deployments_not_ingested"]
    if row["anonymous"]:
        return AUTH_NONE, ["anonymous_deployment"]
    if not deployments:
        return AUTH_UNKNOWN, ["no_deployments"]
    return AUTH_REQUIRED, ["deployment_authentication"]


def bucket_auth(row: Dict) -> Verdict:
    if row["open"]:
        return AUTH_NONE, ["public_access_type"]
    # A read PAR URL is a bearer secret: whoever holds it reads without an OCI identity.
    return AUTH_REQUIRED, ["iam"] + (["unexpired_read_par"] if row["par"] else [])


def autonomous_db_auth(row: Dict) -> Verdict:
    return AUTH_REQUIRED, [DATABASE_CREDENTIALS] + (["mtls_wallet"] if row["mtls"] else [])


def flag_auth(none_reason: str, required_reason: str) -> Callable[[Dict], Verdict]:
    """Resources where one boolean (row["open"]) decides anonymous vs credentials."""
    def verdict(row: Dict) -> Verdict:
        return (AUTH_NONE, [none_reason]) if row["open"] else (AUTH_REQUIRED, [required_reason])
    return verdict


def fixed(state: str, reason: str) -> Callable[[Dict], Verdict]:
    return lambda _row: (state, [reason])


def _q(label: str, returns: str = "") -> str:
    return f"MATCH {COMPARTMENT}(n:{label}) RETURN n.id AS id {returns}"


# label -> (query, verdict function)
RULES: Dict[str, Tuple[str, Callable[[Dict], Verdict]]] = {
    "OCIInstance": (_q("OCIInstance"), fixed(AUTH_UNKNOWN, "self_managed_service")),
    LOAD_BALANCER_LABEL: (_q(LOAD_BALANCER_LABEL), fixed(AUTH_UNKNOWN, "backend_decides")),
    NETWORK_LOAD_BALANCER_LABEL: (_q(NETWORK_LOAD_BALANCER_LABEL), fixed(AUTH_UNKNOWN, "backend_decides")),
    "OCIDbSystem": (_q("OCIDbSystem"), fixed(AUTH_REQUIRED, DATABASE_CREDENTIALS)),
    "OCIDbNode": (
        f"MATCH {COMPARTMENT}(:OCIDbSystem)-[:HAS_DB_NODE]->(n:OCIDbNode) RETURN n.id AS id",
        fixed(AUTH_REQUIRED, DATABASE_CREDENTIALS),
    ),
    "OCIAutonomousDatabase": (
        _q("OCIAutonomousDatabase", ", coalesce(n.is_mtls_connection_required, true) AS mtls"),
        autonomous_db_auth,
    ),
    "OCIOKECluster": (_q("OCIOKECluster"), fixed(AUTH_REQUIRED, "kubernetes_auth")),
    "OCIApiGateway": (
        _q(
            "OCIApiGateway",
            ", n.deployment_ids AS deployments, size(coalesce(n.anonymous_deployment_ids, [])) > 0 AS anonymous",
        ),
        api_gateway_auth,
    ),
    "OCIStorageBucket": (
        _q(
            "OCIStorageBucket",
            f", coalesce(n.public_access_type IN {list(PUBLIC_BUCKET_ACCESS_TYPES)}, false) AS open, "
            "coalesce(n.read_par_expires_at, 0) > timestamp() AS par",
        ),
        bucket_auth,
    ),
    "OCIContainerRepository": (
        _q("OCIContainerRepository", ", coalesce(n.is_public, false) AS open"),
        flag_auth("public_repository", "iam"),
    ),
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
