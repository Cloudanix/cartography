"""
Azure L3: does the resource answer without credentials?

none      anonymous callers get in (public blob container, ACR anonymous pull)
required  credentials are always needed (account keys / Entra ID, DB logins, Kubernetes auth)
unknown   config cannot tell: self-managed software on VMs, LB backends, app code
"""
from typing import Callable
from typing import Dict
from typing import List
from typing import Tuple

import neo4j

from cartography.intel.azure.exposure_layers.gateways import APP_GATEWAY
from cartography.intel.azure.exposure_layers.gateways import FIREWALL
from cartography.intel.azure.exposure_layers.network import SUBSCRIPTION
from cartography.intel.azure.exposure_layers.reach import ACR
from cartography.intel.azure.exposure_layers.reach import AKS
from cartography.intel.azure.exposure_layers.reach import BLOB_CONTAINER
from cartography.intel.azure.exposure_layers.reach import COSMOS
from cartography.intel.azure.exposure_layers.reach import FUNCTION_APP
from cartography.intel.azure.exposure_layers.reach import KEY_VAULT
from cartography.intel.azure.exposure_layers.reach import LB
from cartography.intel.azure.exposure_layers.reach import NIC
from cartography.intel.azure.exposure_layers.reach import SQL_DATABASE
from cartography.intel.azure.exposure_layers.reach import SQL_SERVER
from cartography.intel.azure.exposure_layers.reach import STORAGE
from cartography.intel.azure.exposure_layers.reach import VM
from cartography.intel.azure.exposure_layers.reach import VMSS
from cartography.intel.exposure.layers import AUTH_NONE
from cartography.intel.exposure.layers import auth_props
from cartography.intel.exposure.layers import AUTH_REQUIRED
from cartography.intel.exposure.layers import AUTH_UNKNOWN

Verdict = Tuple[str, List[str]]
# Container access levels (Cypher list) that serve blobs anonymously; "none" / null do not.
_ANONYMOUS = "['container', 'blob']"
# Easy Auth unauthenticated actions that turn a caller without credentials away.
# AllowAnonymous (or unread settings, None) lets the app decide.
EASY_AUTH_REJECTS = frozenset({"redirecttologinpage", "return401", "return403"})
WAF_PREVENTION = "prevention"


def easy_auth(row: Dict) -> Verdict:
    """App Service authentication on and rejecting anonymous callers = required; anything else unknown."""
    if row["auth_enabled"] and str(row["action"] or "").lower() in EASY_AUTH_REJECTS:
        return AUTH_REQUIRED, ["easy_auth"]
    return AUTH_UNKNOWN, ["app_decides"]


def app_gateway(row: Dict) -> Verdict:
    """A WAF in Prevention mode blocks known attack patterns, not anonymous callers: a reason only."""
    waf = ["waf_prevention"] if row["waf_enabled"] and str(row["waf_mode"] or "").lower() == WAF_PREVENTION else []
    return AUTH_UNKNOWN, ["backend_decides"] + waf


def flag_auth(none_reason: str, required_reason: str) -> Callable[[Dict], Verdict]:
    """Resources where one boolean (row["open"]) decides anonymous vs credentials."""
    def verdict(row: Dict) -> Verdict:
        return (AUTH_NONE, [none_reason]) if row["open"] else (AUTH_REQUIRED, [required_reason])
    return verdict


def required_by(flag_reason: str, default_reason: str) -> Callable[[Dict], Verdict]:
    """Always required; row["flag"] only says which credential (e.g. Entra-only vs keys)."""
    return lambda row: (AUTH_REQUIRED, [flag_reason if row["flag"] else default_reason])


def fixed(state: str, reason: str) -> Callable[[Dict], Verdict]:
    return lambda _row: (state, [reason])


def _q(label: str, returns: str = "") -> str:
    return f"MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:{label}) RETURN n.id AS id {returns}"


# Anonymous blob access needs both the account switch (null on old accounts = allowed)
# and a container access level.
_STORAGE_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureStorageAccount)
OPTIONAL MATCH (n)-[:USES]->(:AzureStorageBlobService)-[:CONTAINS]->(c:AzureStorageBlobContainer)
WHERE c.publicaccess IN {_ANONYMOUS}
WITH n, count(c) AS anonymous
RETURN n.id AS id, coalesce(n.allowBlobPublicAccess, true) AND anonymous > 0 AS open
"""

_BLOB_CONTAINER_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(a:AzureStorageAccount)-[:USES]->(:AzureStorageBlobService)
    -[:CONTAINS]->(n:AzureStorageBlobContainer)
RETURN n.id AS id, coalesce(a.allowBlobPublicAccess, true) AND coalesce(n.publicaccess IN {_ANONYMOUS}, false) AS open
"""

_SQL_DATABASE_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(s:AzureSQLServer)-[:RESOURCE]->(n:AzureSQLDatabase)
RETURN n.id AS id, coalesce(s.azureADOnlyAuthentication, false) AS flag
"""

# label -> (query, verdict function)
RULES: Dict[str, Tuple[str, Callable[[Dict], Verdict]]] = {
    STORAGE: (_STORAGE_QUERY, flag_auth("anonymous_blob_container", "account_keys_or_entra_id")),
    BLOB_CONTAINER: (_BLOB_CONTAINER_QUERY, flag_auth("anonymous_container_access", "account_keys_or_entra_id")),
    SQL_SERVER: (
        _q(SQL_SERVER, ", coalesce(n.azureADOnlyAuthentication, false) AS flag"),
        required_by("entra_id_only", "database_credentials"),
    ),
    SQL_DATABASE: (_SQL_DATABASE_QUERY, required_by("entra_id_only", "database_credentials")),
    COSMOS: (
        _q(COSMOS, ", coalesce(n.disableLocalAuth, false) AS flag"),
        required_by("entra_id_only", "account_keys_or_entra_id"),
    ),
    KEY_VAULT: (_q(KEY_VAULT), fixed(AUTH_REQUIRED, "entra_id")),
    AKS: (_q(AKS), fixed(AUTH_REQUIRED, "kubernetes_auth")),
    ACR: (
        _q(ACR, ", coalesce(n.anonymous_pull_enabled, false) AS open"),
        flag_auth("anonymous_pull", "registry_credentials"),
    ),
    FUNCTION_APP: (
        _q(FUNCTION_APP, ", n.auth_enabled AS auth_enabled, n.unauthenticated_client_action AS action"), easy_auth,
    ),
    VM: (_q(VM), fixed(AUTH_UNKNOWN, "self_managed_service")),
    VMSS: (_q(VMSS), fixed(AUTH_UNKNOWN, "self_managed_service")),
    NIC: (_q(NIC), fixed(AUTH_UNKNOWN, "self_managed_service")),
    LB: (_q(LB), fixed(AUTH_UNKNOWN, "backend_decides")),
    APP_GATEWAY: (_q(APP_GATEWAY, ", n.waf_enabled AS waf_enabled, n.waf_mode AS waf_mode"), app_gateway),
    FIREWALL: (_q(FIREWALL), fixed(AUTH_UNKNOWN, "backend_decides")),
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
