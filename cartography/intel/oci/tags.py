# OCI freeform/defined tag ingestion.
# Shared helper modeled on cartography.intel.gcp.label: each service module calls
# sync_tags() on the raw (hyphen-keyed) API payload it already fetched, so tag
# ingestion adds no extra API calls.
import logging
import time
from typing import Any
from typing import Dict
from typing import List

import neo4j

from cartography.util import batch
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


def get_tags_list(data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Flatten freeform-tags and defined-tags off raw OCI API dicts.
    Defined tags are namespaced as "<namespace>.<key>".
    """
    tags: List[Dict[str, Any]] = []
    for item in data:
        resource_id = item.get('id')
        if not resource_id:
            continue

        freeform = item.get('freeform-tags') or {}
        if isinstance(freeform, dict):
            for key, value in freeform.items():
                tags.append(_make_tag(resource_id, key, value))

        defined = item.get('defined-tags') or {}
        if isinstance(defined, dict):
            for namespace, entries in defined.items():
                if not isinstance(entries, dict):
                    continue
                for key, value in entries.items():
                    tags.append(_make_tag(resource_id, f"{namespace}.{key}", value))

    return tags


def _make_tag(resource_id: str, key: str, value: Any) -> Dict[str, str]:
    return {
        'id': f"{resource_id}/tag/{key}",
        'key': key,
        'value': str(value),
        'resource_id': resource_id,
    }


def _load_tags_tx(
    tx: neo4j.Transaction,
    tags: List[Dict[str, Any]],
    resource_label: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    # Neo4j cannot parameterize labels, so resource_label is interpolated. It is
    # always a hardcoded literal at the call site, never user input.
    ingest_tags = """
    UNWIND $data AS tag
    MATCH (r:""" + resource_label + """{id: tag.resource_id})
    <-[:RESOURCE]-(:OCICompartment)<-[:OWNER]-(:OCITenancy{id: $OCI_TENANCY_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID})
    MERGE (t:OCITag{id: tag.id})
    ON CREATE SET t.firstseen = timestamp()
    SET t.lastupdated = $update_tag,
    t.key = tag.key,
    t.value = tag.value
    MERGE (r)-[rel:TAGGED]->(t)
    ON CREATE SET rel.firstseen = timestamp()
    SET rel.lastupdated = $update_tag
    """

    tx.run(
        ingest_tags,
        data=tags,
        update_tag=update_tag,
        OCI_TENANCY_ID=common_job_parameters['OCI_TENANCY_ID'],
        WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
    )


@timeit
def load_tags(
    neo4j_session: neo4j.Session,
    tags: List[Dict[str, Any]],
    resource_label: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    for tags_batch in batch(tags, size=500):
        neo4j_session.execute_write(
            _load_tags_tx, tags_batch, resource_label, update_tag, common_job_parameters,
        )


def cleanup_tags(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('oci_import_tags_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_tags(
    neo4j_session: neo4j.Session,
    data: List[Dict[str, Any]],
    resource_label: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    if data:
        tags = get_tags_list(data)
        if tags:
            logger.info(f"Loading {len(tags)} OCI tags for {resource_label}")
            load_tags(neo4j_session, tags, resource_label, update_tag, common_job_parameters)
    logger.debug(f"Time to process OCI tags for {resource_label}: {time.perf_counter() - tic:0.4f} seconds")
