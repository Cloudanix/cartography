import logging
import math
import time
from typing import Dict
from typing import List

import neo4j

from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

# Cypher fragment walking from a labeled resource back to its owning GCPProject.
# Most resources hang directly off the project; the ones below are owned by a
# parent resource instead, so a direct-only MATCH silently drops their labels.
# Every entry here needs a matching statement in gcp_labels_cleanup.json
# (asserted by the unit tests).
DEFAULT_OWNERSHIP_PATH = '<-[:RESOURCE]-'
OWNERSHIP_PATHS: Dict[str, str] = {
    'GCPKMSCryptoKey': '<-[:RESOURCE]-(:GCPKMSKeyRing)<-[:RESOURCE]-',
}


@timeit
def get_labels_list(data: List[Dict]) -> List[Dict]:
    labels_data = []
    for item in data:
        labels = item.get('labels', {})
        if type(labels) is not dict:
            labels = {}
        for key, value in labels.items():
            label = {}
            label['id'] = f"{item.get('id', '')}/label/{key}"
            label['key'] = key
            label['value'] = value
            label['resource_id'] = item.get('id', None)

            if label['resource_id']:
                labels_data.append(label)

    return labels_data


def load_labels(session: neo4j.Session, data_list: List[Dict], update_tag: int, common_job_parameters: Dict, service_label: str) -> None:
    iteration_size = 500
    total_items = len(data_list)
    total_iterations = math.ceil(len(data_list) / iteration_size)
    logger.info(f"total labels: {total_items}")
    logger.info(f"total iterations: {total_iterations}")

    for counter in range(0, total_iterations):
        start = iteration_size * (counter)

        if start + iteration_size >= total_items:
            end = total_items
            labels = data_list[start:]

        else:
            end = start + iteration_size
            labels = data_list[start:end]

        session.execute_write(_load_labels_tx, labels, update_tag, common_job_parameters, service_label)

        logger.info(f"Iteration {counter + 1} of {total_iterations}. {start} - {end} - {len(labels)}")


def _load_labels_tx(tx: neo4j.Transaction, labels: List[Dict], update_tag: int, common_job_parameters: Dict, service_label: str) -> None:
    # Neo4j cannot parameterize labels or relationship types, so service_label and
    # the ownership path are interpolated. Both are hardcoded literals — the label
    # comes from the call site, the path from OWNERSHIP_PATHS — never user input.
    ownership_path = OWNERSHIP_PATHS.get(service_label, DEFAULT_OWNERSHIP_PATH)
    ingest_label = """
    UNWIND $data AS label
    MATCH (r:""" + service_label + """{id:label.resource_id})
    """ + ownership_path + """(:GCPProject{id: $GCP_PROJECT_ID})<-[:OWNER]-(:GCPOrganization{id:$GCP_ORGANIZATION_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID})
    MERGE (l:GCPLabel{id: label.id})
    ON CREATE SET l.firstseen = timestamp()
    SET l.lastupdated = $update_tag,
    l.value = label.value,
    l.key = label.key
    MERGE (r)-[lb:LABELED]->(l)
    ON CREATE SET lb.firstseen = timestamp()
    SET lb.lastupdated = $update_tag
    """

    tx.run(
        ingest_label,
        data=labels,
        update_tag=update_tag,
        GCP_PROJECT_ID=common_job_parameters['GCP_PROJECT_ID'],
        GCP_ORGANIZATION_ID=common_job_parameters['GCP_ORGANIZATION_ID'],
        WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
    )


def cleanup_labels(neo4j_session: neo4j.Session, common_job_parameters: Dict, service_name: str) -> None:
    logger.info(f"Cleaning Labels for {service_name}")
    run_cleanup_job('gcp_labels_cleanup.json', neo4j_session, common_job_parameters)


def sync_labels(
    neo4j_session: neo4j.Session, data: List[Dict], update_tag: int, common_job_parameters: Dict,
    service_name: str, service_label: str,
) -> None:
    tic = time.perf_counter()
    common_job_parameters['service_labels'].append(service_label)
    if len(data) > 0:
        labels_list = get_labels_list(data)
        if len(labels_list) > 0:
            logger.info(f"BEGIN Loading {len(labels_list)} Labels for {service_name}")
            load_labels(neo4j_session, labels_list, update_tag, common_job_parameters, service_label)
            logger.info(f"END Loading Labels for {service_name}")
    logger.info(f"Time to process GCP labels for {service_name}: {time.perf_counter() - tic:0.4f} seconds")
