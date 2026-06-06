"""AWS Backup intel — sync backup jobs and protected resources into the graph.

Records the facts the compliance backup checks (rules 50-57) consume: which resources have a backup
recovery point (a job carrying a RecoveryPointArn) and which are currently protected
(ListProtectedResources). No compliance logic here — only ingestion.
"""

import logging
import time
from typing import Any
from typing import Dict
from typing import List

import boto3
import neo4j

from cartography.client.core.tx import load
from cartography.graph.job import GraphJob
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.models.aws.backup.jobs import AWSBackupJobSchema
from cartography.models.aws.backup.jobs import AWSBackupProtectedResourceSchema
from cartography.stats import get_stats_client
from cartography.util import aws_handle_regions
from cartography.util import dict_value_to_str
from cartography.util import merge_module_sync_metadata
from cartography.util import timeit

logger = logging.getLogger(__name__)
stat_handler = get_stats_client(__name__)


@timeit
@aws_handle_regions
def get_backup_jobs(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('backup', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('list_backup_jobs')
    jobs: List[Dict] = []
    for page in paginator.paginate():
        jobs.extend(page.get('BackupJobs', []))
    return jobs


@timeit
@aws_handle_regions
def get_protected_resources(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('backup', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('list_protected_resources')
    resources: List[Dict] = []
    for page in paginator.paginate():
        resources.extend(page.get('Results', []))
    return resources


@timeit
def transform_backup_jobs(jobs: List[Dict]) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for job in jobs:
        job_id = job.get('BackupJobId')
        if not job_id:
            continue
        transformed.append({
            'BackupJobId': job_id,
            'ResourceArn': job.get('ResourceArn'),
            'RecoveryPointArn': job.get('RecoveryPointArn'),
            'CreationDate': dict_value_to_str(job, 'CreationDate'),
            'CompletionDate': dict_value_to_str(job, 'CompletionDate'),
            'State': job.get('State'),
            'BackupVaultName': job.get('BackupVaultName'),
            'ResourceType': job.get('ResourceType'),
        })
    return transformed


@timeit
def transform_protected_resources(resources: List[Dict]) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for resource in resources:
        resource_arn = resource.get('ResourceArn')
        if not resource_arn:
            continue
        transformed.append({
            'ResourceArn': resource_arn,
            'ResourceType': resource.get('ResourceType'),
            'LastBackupTime': dict_value_to_str(resource, 'LastBackupTime'),
        })
    return transformed


@timeit
def load_backup_jobs(
    neo4j_session: neo4j.Session, data: List[Dict[str, Any]], region: str, current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    logger.info(f"Loading {len(data)} AWS Backup jobs for region '{region}' into graph.")
    load(
        neo4j_session,
        AWSBackupJobSchema(),
        data,
        lastupdated=aws_update_tag,
        Region=region,
        AWS_ID=current_aws_account_id,
    )


@timeit
def load_protected_resources(
    neo4j_session: neo4j.Session, data: List[Dict[str, Any]], region: str, current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    logger.info(f"Loading {len(data)} AWS Backup protected resources for region '{region}' into graph.")
    load(
        neo4j_session,
        AWSBackupProtectedResourceSchema(),
        data,
        lastupdated=aws_update_tag,
        Region=region,
        AWS_ID=current_aws_account_id,
    )


@timeit
def cleanup_backup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    GraphJob.from_node_schema(AWSBackupJobSchema(), common_job_parameters).run(neo4j_session)
    GraphJob.from_node_schema(AWSBackupProtectedResourceSchema(), common_job_parameters).run(neo4j_session)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing AWS Backup for account '%s', at %s.", current_aws_account_id, tic)

    for region in regions:
        logger.info("Syncing AWS Backup for region '%s' in account '%s'.", region, current_aws_account_id)
        jobs = transform_backup_jobs(get_backup_jobs(boto3_session, region))
        load_backup_jobs(neo4j_session, jobs, region, current_aws_account_id, update_tag)
        protected = transform_protected_resources(get_protected_resources(boto3_session, region))
        load_protected_resources(neo4j_session, protected, region, current_aws_account_id, update_tag)

    cleanup_backup(neo4j_session, common_job_parameters)
    merge_module_sync_metadata(
        neo4j_session,
        group_type='AWSAccount',
        group_id=current_aws_account_id,
        synced_type='AWSBackupJob',
        update_tag=update_tag,
        stat_handler=stat_handler,
    )

    toc = time.perf_counter()
    logger.info(f"Time to process AWS Backup: {toc - tic:0.4f} seconds")
