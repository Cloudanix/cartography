import json
import logging
from typing import Dict
from typing import List

import time
import neo4j
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from cartography.util import run_cleanup_job
from . import label
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_logging_metrics(logging: Resource, project_id: str) -> List[Dict]:
    metrics = []
    try:
        req = logging.projects().metrics().list(parent=f"projects/{project_id}")
        while req is not None:
            res = req.execute()
            if res.get('metrics'):
                for metric in res['metrics']:
                    metric['region'] = 'global'
                    metric['id'] = metric['name']
                    metric['metric_name'] = metric.get('name').split('/')[-1]
                    metrics.append(metric)
            req = logging.projects().metrics().list_next(previous_request=req, previous_response=res)


        return metrics
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
            logger.warning(
                (
                    "Could not retrieve logging metrics on project %s due to permissions issues. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def load_logging_metrics(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.write_transaction(load_logging_metrics_tx, data_list, project_id, update_tag)


@timeit
def load_logging_metrics_tx(
    tx: neo4j.Transaction, data: List[Dict],
    project_id: str, gcp_update_tag: int,
) -> None:

    query = """
    UNWIND {Records} as record
    MERGE (metric:GCPLoggingMetric{id:record.id})
    ON CREATE SET
        metric.firstseen = timestamp()
    SET
        metric.lastupdated = {gcp_update_tag},
        metric.region = record.region,
        metric.name = record.metric_name,
        metric.description = record.description,
        metric.filter = record.filter,
        metric.bucket_name = record.bucketName,
        metric.disabled = record.disabled,
        metric.value_extractor = record.valueExtractor,
        metric.create_time = record.createTime,
        metric.update_time = record.updateTime
    WITH metric
    MATCH (owner:GCPProject{id:{ProjectId}})
    MERGE (owner)-[r:RESOURCE]->(metric)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        query,
        Records=data,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_logging_metrics(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_logging_metrics_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_logging_metrics(
    neo4j_session: neo4j.Session, logging: Resource, project_id: str,
    gcp_update_tag: int, common_job_parameters: Dict,
) -> None:

    metrics = get_logging_metrics(logging, project_id)

    if common_job_parameters.get('pagination', {}).get('cloud_logging', None):
        pageNo = common_job_parameters.get("pagination", {}).get("cloud_logging", None)["pageNo"]
        pageSize = common_job_parameters.get("pagination", {}).get("cloud_logging", None)["pageSize"]
        totalPages = len(metrics) / pageSize
        if int(totalPages) != totalPages:
            totalPages = totalPages + 1
        totalPages = int(totalPages)
        if pageNo < totalPages or pageNo == totalPages:
            logger.info(f'pages process for logging metrics {pageNo}/{totalPages} pageSize is {pageSize}')
        page_start = (common_job_parameters.get('pagination', {}).get('cloud_logging', None)[
                        'pageNo'] - 1) * common_job_parameters.get('pagination', {}).get('cloud_logging', None)['pageSize']
        page_end = page_start + common_job_parameters.get('pagination', {}).get('cloud_logging', None)['pageSize']
        if page_end > len(metrics) or page_end == len(metrics):
            metrics = metrics[page_start:]
        else:
            has_next_page = True
            metrics = metrics[page_start:page_end]
            common_job_parameters['pagination']['cloud_logging']['hasNextPage'] = has_next_page

    load_logging_metrics(neo4j_session, metrics, project_id, gcp_update_tag)
    cleanup_logging_metrics(neo4j_session, common_job_parameters)


def sync(
    neo4j_session: neo4j.Session, logging: Resource, project_id: str, gcp_update_tag: int,
    common_job_parameters: dict, regions: list,
) -> None:

    tic = time.perf_counter()

    logger.info(f"Syncing logging for project {project_id}, at {tic}")

    sync_logging_metrics(neo4j_session, logging, project_id,
                                  gcp_update_tag, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process logging: {toc - tic:0.4f} seconds")