"""
AWS L4 input: what software runs, as `<product>@<version>`. cloudanix-web joins these to CVEs
(together with inventory-sync data), so nothing here knows about vulnerabilities.
"""
import re
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.aws.exposure_layers.network import ACCOUNT
from cartography.intel.exposure.layers import software_props
from cartography.intel.exposure.layers import SOURCE_IMAGE_NAME
from cartography.intel.exposure.layers import SOURCE_MANAGED_CONFIG
from cartography.intel.exposure.software import identity
from cartography.intel.exposure.software import os_from_image_name

# python3.12, nodejs20.x, java17, dotnet8, ruby3.3, go1.x, provided.al2023
_RUNTIME = re.compile(r"^(python|nodejs|java|dotnet|dotnetcore|ruby|go)(\d+(?:\.\d+)?)")
_PROVIDED = re.compile(r"^provided(?:\.al(\d+))?$")


def lambda_runtime(runtime: Optional[str]) -> Optional[str]:
    """
    >>> lambda_runtime("nodejs20.x")
    'nodejs@20'
    >>> lambda_runtime("provided.al2023")
    'amazon-linux@2023'
    """
    if not runtime:
        return None
    provided = _PROVIDED.match(runtime)
    if provided:
        return identity("amazon-linux", provided.group(1) or "1")
    match = _RUNTIME.match(runtime)
    return identity(match.group(1), match.group(2)) if match else None


def search_engine(version: Optional[str]) -> Optional[str]:
    """ESDomain versions: "OpenSearch_2.11" or plain "7.10" (Elasticsearch)."""
    if not version:
        return None
    if version.lower().startswith("opensearch_"):
        return identity("opensearch", version.split("_", 1)[1])
    return identity("elasticsearch", version)


Extractor = Callable[[Dict], Tuple[List[Optional[str]], str]]


def _engine(row: Dict) -> Tuple[List[Optional[str]], str]:
    return [identity(row.get("engine"), row.get("version"))], SOURCE_MANAGED_CONFIG


def _q(label: str, returns: str) -> str:
    return f"MATCH {ACCOUNT}-[:RESOURCE]->(n:{label}) RETURN n.id AS id, {returns}"


RULES: Dict[str, Tuple[str, Extractor]] = {
    "RDSInstance": (_q("RDSInstance", "n.engine AS engine, n.engine_version AS version"), _engine),
    "RDSCluster": (_q("RDSCluster", "n.engine AS engine, n.engine_version AS version"), _engine),
    "ElasticacheCluster": (_q("ElasticacheCluster", "n.engine AS engine, n.engine_version AS version"), _engine),
    "EKSCluster": (
        _q("EKSCluster", "n.version AS version"),
        lambda r: ([identity("kubernetes", r.get("version"))], SOURCE_MANAGED_CONFIG),
    ),
    "ESDomain": (
        _q("ESDomain", "n.elasticsearch_version AS version"),
        lambda r: ([search_engine(r.get("version"))], SOURCE_MANAGED_CONFIG),
    ),
    "AWSLambda": (
        _q("AWSLambda", "n.runtime AS runtime"),
        lambda r: ([lambda_runtime(r.get("runtime"))], SOURCE_MANAGED_CONFIG),
    ),
    "EC2Instance": (
        f"""MATCH {ACCOUNT}-[:RESOURCE]->(n:EC2Instance)
        OPTIONAL MATCH (n)-[:CHILDREN]->(img:EC2Image)
        RETURN n.id AS id, img.name AS name, img.description AS description, img.location AS location""",
        lambda r: ([os_from_image_name(r.get("name"), r.get("location"), r.get("description"))], SOURCE_IMAGE_NAME),
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
