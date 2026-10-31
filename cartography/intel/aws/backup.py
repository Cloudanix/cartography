import logging
import time
from datetime import datetime
from datetime import timedelta
from datetime import timezone
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
from cartography.util import aws_handle_regions
from cartography.util import dict_value_to_iso
from cartography.util import timeit

logger = logging.getLogger(__name__)

# Job history is unbounded, so only recent jobs are ingested. ListBackupJobs itself only returns the
# last 30 days, and the rules that read jobs need the latest recovery point per resource (the
# "within N days" rules; AWS Config caps the same check at 744h) or the retention of each recent one.
BACKUP_JOB_LOOKBACK_DAYS = 30
# Per-region ceiling (10 list calls; ~330 resources backed up daily for 30 days) so a busy account cannot
# stall the sync; beyond it the rest is dropped with a warning. If it triggers in practice, keep only the
# latest job per resource rather than raising it.
MAX_BACKUP_JOBS_PER_REGION = 10000
# Largest MaxResults ListBackupJobs and ListProtectedResources accept: fewest calls per resource.
BACKUP_PAGE_SIZE = 1000


@timeit
@aws_handle_regions
def get_backup_jobs(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('backup', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('list_backup_jobs')
    created_after = datetime.now(timezone.utc) - timedelta(days=BACKUP_JOB_LOOKBACK_DAYS)
    jobs: List[Dict] = []
    pages = paginator.paginate(ByCreatedAfter=created_after, PaginationConfig={'PageSize': BACKUP_PAGE_SIZE})
    for page in pages:
        jobs.extend(page.get('BackupJobs', []))
        if len(jobs) >= MAX_BACKUP_JOBS_PER_REGION:
            logger.warning(
                f"AWS Backup: more than {MAX_BACKUP_JOBS_PER_REGION} jobs in the last {BACKUP_JOB_LOOKBACK_DAYS} days "
                f"in region '{region}'; ingesting the first {MAX_BACKUP_JOBS_PER_REGION} only.",
            )
            return jobs[:MAX_BACKUP_JOBS_PER_REGION]
    return jobs


@timeit
@aws_handle_regions
def get_protected_resources(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('backup', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('list_protected_resources')
    resources: List[Dict] = []
    for page in paginator.paginate(PaginationConfig={'PageSize': BACKUP_PAGE_SIZE}):
        resources.extend(page.get('Results', []))
    return resources


def transform_backup_jobs(jobs: List[Dict]) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for job in jobs:
        if not job.get('BackupJobId'):
            continue
        transformed.append({
            'BackupJobId': job['BackupJobId'],
            'ResourceArn': job.get('ResourceArn'),
            'ResourceType': job.get('ResourceType'),
            'RecoveryPointArn': job.get('RecoveryPointArn'),
            'RecoveryPointDeleteAfterDays': (job.get('RecoveryPointLifecycle') or {}).get('DeleteAfterDays'),
            'CreationDate': dict_value_to_iso(job, 'CreationDate'),
            'CompletionDate': dict_value_to_iso(job, 'CompletionDate'),
            'State': job.get('State'),
            'BackupVaultName': job.get('BackupVaultName'),
            'BackupVaultArn': job.get('BackupVaultArn'),
        })
    return transformed


def transform_protected_resources(resources: List[Dict]) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for resource in resources:
        if not resource.get('ResourceArn'):
            continue
        transformed.append({
            'ResourceArn': resource['ResourceArn'],
            'ResourceType': resource.get('ResourceType'),
            'ResourceName': resource.get('ResourceName'),
            'LastBackupTime': dict_value_to_iso(resource, 'LastBackupTime'),
            'LastRecoveryPointArn': resource.get('LastRecoveryPointArn'),
        })
    return transformed


@timeit
def load_backup_jobs(
    neo4j_session: neo4j.Session,
    data: List[Dict[str, Any]],
    region: str,
    current_aws_account_id: str,
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
    neo4j_session: neo4j.Session,
    data: List[Dict[str, Any]],
    region: str,
    current_aws_account_id: str,
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
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict,
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

    toc = time.perf_counter()
    logger.info(f"Time to process AWS Backup: {toc - tic:0.4f} seconds")
