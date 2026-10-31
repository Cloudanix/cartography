"""
OCI L4 input: what software runs, as `<product>@<version>`. cloudanix-web joins these to CVEs,
so nothing here knows about vulnerabilities.
"""
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
from cartography.intel.oci.exposure_layers.network import COMPARTMENT

KUBERNETES = "kubernetes"
ORACLE_DATABASE = "oracle-database"


def kubernetes(version: Optional[str]) -> Optional[str]:
    """
    OKE reports "v1.29.1"; drop the "v" so identities match other clouds.

    >>> kubernetes("v1.29.1")
    'kubernetes@1.29.1'
    """
    return identity(KUBERNETES, (version or "").lstrip("vV") or None)


def instance_os(row: Dict) -> Optional[str]:
    """Image display name ("Oracle-Linux-8.9-2024.01.26-0") first, then image OS + version."""
    os_and_version = " ".join(v for v in (row.get("os"), row.get("os_version")) if v)
    return os_from_image_name(row.get("image"), os_and_version)


Extractor = Callable[[Dict], Tuple[List[Optional[str]], str]]


def _q(label: str, returns: str) -> str:
    return f"MATCH {COMPARTMENT}(n:{label}) RETURN n.id AS id, {returns}"


def _database(row: Dict) -> Tuple[List[Optional[str]], str]:
    return [identity(ORACLE_DATABASE, v) for v in row["versions"]], SOURCE_MANAGED_CONFIG


def _kubernetes(row: Dict) -> Tuple[List[Optional[str]], str]:
    return [kubernetes(row.get("version"))], SOURCE_MANAGED_CONFIG


RULES: Dict[str, Tuple[str, Extractor]] = {
    "OCIOKECluster": (_q("OCIOKECluster", "n.kubernetes_version AS version"), _kubernetes),
    "OCIOKENodePool": (_q("OCIOKENodePool", "n.kubernetes_version AS version"), _kubernetes),
    "OCIAutonomousDatabase": (_q("OCIAutonomousDatabase", "[n.db_version] AS versions"), _database),
    # Homes carry the full patch level ("19.22.0.0"); the system only the base release.
    "OCIDbSystem": (
        f"""MATCH {COMPARTMENT}(n:OCIDbSystem)
        OPTIONAL MATCH (n)-[:HAS_DB_HOME]->(h:OCIDbHome)
        WITH n, collect(h.db_version) AS home_versions
        RETURN n.id AS id, [n.version] + home_versions AS versions""",
        _database,
    ),
    "OCIInstance": (
        f"""MATCH {COMPARTMENT}(n:OCIInstance)
        OPTIONAL MATCH (img:OCIImage{{id: n.image_id}})
        RETURN n.id AS id, img.display_name AS image, n.vm_os AS os, n.vm_os_version AS os_version""",
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
