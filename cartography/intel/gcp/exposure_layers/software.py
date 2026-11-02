"""
GCP L4 input: what software runs, as `<product>@<version>`. cloudanix-web joins these to CVEs,
so nothing here knows about vulnerabilities.
"""
import re
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.exposure.layers import software_props
from cartography.intel.exposure.layers import SOURCE_IMAGE_NAME
from cartography.intel.exposure.layers import SOURCE_MANAGED_CONFIG
from cartography.intel.exposure.software import identity
from cartography.intel.exposure.software import os_from_image_name
from cartography.intel.gcp.exposure_layers.network import PROJECT

# Runtimes whose number is <major><minor> with a one-digit major: python312, go121, ruby33, php82.
_SPLIT_MAJOR = frozenset({"python", "go", "ruby", "php"})
_RUNTIME = re.compile(r"^([a-z]+?)(\d+)$")


def sql_version(database_version: Optional[str]) -> Optional[str]:
    """
    Cloud SQL databaseVersion -> identity; edition suffixes are dropped.

    >>> sql_version("MYSQL_8_0")
    'mysql@8.0'
    >>> sql_version("SQLSERVER_2019_STANDARD")
    'sqlserver@2019'
    """
    if not database_version:
        return None
    product, *rest = database_version.split("_")
    digits: List[str] = []
    for part in rest:
        if not part.isdigit():
            break
        digits.append(part)
    return identity(product, ".".join(digits)) if digits else None


def function_runtime(runtime: Optional[str]) -> Optional[str]:
    """
    Cloud Functions runtime -> identity.

    >>> function_runtime("python312")
    'python@3.12'
    >>> function_runtime("nodejs20")
    'nodejs@20'
    """
    match = _RUNTIME.match(str(runtime or "").lower())
    if not match:
        return None
    product, number = match.groups()
    if product in _SPLIT_MAJOR and len(number) > 1:
        return identity(product, f"{number[0]}.{number[1:]}")
    return identity(product, number)


def _last_segment(uri: Optional[str]) -> Optional[str]:
    return str(uri).rstrip("/").rsplit("/", 1)[-1] if uri else None


def instance_os(row: Dict) -> Optional[str]:
    """Only image and license names, never full URIs: project names like cos-cloud would mislead."""
    licenses = [_last_segment(lic) for lic in row.get("licenses") or []]
    return os_from_image_name(_last_segment(row.get("source_image")), row.get("name"), row.get("family"), *licenses)


Extractor = Callable[[Dict], Tuple[List[Optional[str]], str]]


def _q(label: str, returns: str) -> str:
    return f"MATCH {PROJECT}-[:RESOURCE]->(n:{label}) RETURN n.id AS id, {returns}"


RULES: Dict[str, Tuple[str, Extractor]] = {
    "GKECluster": (
        _q("GKECluster", "n.current_master_version AS version"),
        lambda r: ([identity("kubernetes", r.get("version"))], SOURCE_MANAGED_CONFIG),
    ),
    "GCPSQLInstance": (
        _q("GCPSQLInstance", "n.databaseVersion AS version"),
        lambda r: ([sql_version(r.get("version"))], SOURCE_MANAGED_CONFIG),
    ),
    "GCPFunction": (
        _q("GCPFunction", "n.runtime AS runtime"),
        lambda r: ([function_runtime(r.get("runtime"))], SOURCE_MANAGED_CONFIG),
    ),
    "GCPInstance": (
        f"""MATCH {PROJECT}-[:RESOURCE]->(n:GCPInstance)
        OPTIONAL MATCH (n)-[:HAS]->(img:GCPImage)
        WITH n, head(collect(img)) AS img
        RETURN n.id AS id, n.source_image AS source_image, img.name AS name, img.family AS family,
            img.licenses AS licenses""",
        lambda r: ([instance_os(r)], SOURCE_IMAGE_NAME),
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
