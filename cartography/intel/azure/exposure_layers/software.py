"""
Azure L4 input: what software runs, as `<product>@<version>`. cloudanix-web joins these to
CVEs, so nothing here knows about vulnerabilities.
"""
import re
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.azure.exposure_layers.network import SUBSCRIPTION
from cartography.intel.azure.exposure_layers.reach import AKS
from cartography.intel.azure.exposure_layers.reach import FUNCTION_APP
from cartography.intel.azure.exposure_layers.reach import SQL_SERVER
from cartography.intel.azure.exposure_layers.reach import SQL_SERVER_ENGINE
from cartography.intel.azure.exposure_layers.reach import VM
from cartography.intel.exposure.layers import software_props
from cartography.intel.exposure.layers import SOURCE_IMAGE_NAME
from cartography.intel.exposure.layers import SOURCE_MANAGED_CONFIG
from cartography.intel.exposure.software import identity
from cartography.intel.exposure.software import os_from_image_name

# App Service stack names -> products, aligned with the AWS Lambda runtime vocabulary.
_STACKS = {
    "python": "python", "node": "nodejs", "java": "java", "php": "php", "powershell": "powershell",
    "dotnet": "dotnet", "dotnetcore": "dotnet", "dotnet-isolated": "dotnet",
}
# "PYTHON|3.11", "NODE|18-lts", "DOTNET-ISOLATED|8.0", "JAVA|17-java17"
_LINUX_FX = re.compile(r"^([a-z-]+)\|(\d+(?:\.\d+)?)")
_VERSION = re.compile(r"(\d+(?:\.\d+)?)")


def linux_stack(linux_fx_version: Optional[str]) -> Optional[str]:
    """
    >>> linux_stack("NODE|18-lts")
    'nodejs@18'
    """
    match = _LINUX_FX.match(str(linux_fx_version or "").lower())
    if not match or match.group(1) not in _STACKS:
        return None
    return identity(_STACKS[match.group(1)], match.group(2))


def _windows_version(product: str, raw: Optional[str]) -> Optional[str]:
    match = _VERSION.search(str(raw or ""))
    return identity(product, match.group(1)) if match else None


def function_runtime(row: Dict) -> Optional[str]:
    """
    Linux sites name the stack in linux_fx_version; Windows sites set one version field
    ("~18" for Node). net_framework_version is always defaulted, so it says nothing.
    """
    linux = linux_stack(row.get("linux_fx"))
    if linux or row.get("linux_fx"):
        return linux
    for product, key in (("nodejs", "node"), ("python", "python"), ("java", "java")):
        found = _windows_version(product, row.get(key))
        if found:
            return found
    return None


def sql_engine(row: Dict) -> Optional[str]:
    """
    PostgreSQL / MySQL major versions. ponytail: Azure SQL Database reports API version
    "12.0" for every evergreen server, so it yields no identity.
    """
    if row.get("engine") == SQL_SERVER_ENGINE:
        return None
    return identity(row.get("engine"), row.get("version"))


Extractor = Callable[[Dict], Tuple[List[Optional[str]], str]]


def _q(label: str, returns: str) -> str:
    return f"MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:{label}) RETURN n.id AS id, {returns}"


RULES: Dict[str, Tuple[str, Extractor]] = {
    VM: (
        _q(VM, "n.offer AS offer, n.sku AS sku"),
        lambda r: ([os_from_image_name(r.get("offer"), r.get("sku"))], SOURCE_IMAGE_NAME),
    ),
    AKS: (
        _q(AKS, "n.kubernetesVersion AS version"),
        lambda r: ([identity("kubernetes", r.get("version"))], SOURCE_MANAGED_CONFIG),
    ),
    SQL_SERVER: (
        _q(SQL_SERVER, "n.engine AS engine, coalesce(n.engineVersion, n.version) AS version"),
        lambda r: ([sql_engine(r)], SOURCE_MANAGED_CONFIG),
    ),
    FUNCTION_APP: (
        f"""MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureFunctionApp)
        OPTIONAL MATCH (n)-[:CONTAIN]->(c:AzureFunctionAppConfiguration)
        WITH n, head(collect(c)) AS c
        RETURN n.id AS id, c.linux_fx_version AS linux_fx, c.node_version AS node,
            c.python_version AS python, c.java_version AS java""",
        lambda r: ([function_runtime(r)], SOURCE_MANAGED_CONFIG),
    ),
}


def compute(session: neo4j.Session, params: Dict) -> Dict[str, Dict[str, Dict]]:
    """label -> node id -> L4 properties."""
    out: Dict[str, Dict[str, Dict]] = {}
    for label, (query, extract) in RULES.items():
        out[label] = {}
        for row in session.run(query, **params):
            identities, source = extract(dict(row))
            out[label][row["id"]] = software_props(identities, source)
    return out
