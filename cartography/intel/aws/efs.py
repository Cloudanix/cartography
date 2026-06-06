"""AWS EFS intel — sync Elastic File Systems into the graph."""

import logging
import time
from typing import Any
from typing import Dict
from typing import List

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load
from cartography.graph.job import GraphJob
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.models.aws.efs.filesystems import EFSFileSystemSchema
from cartography.stats import get_stats_client
from cartography.util import aws_handle_regions
from cartography.util import dict_value_to_str
from cartography.util import merge_module_sync_metadata
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()
stat_handler = get_stats_client(__name__)


@timeit
@aws_handle_regions
def get_efs_file_systems(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('efs', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_file_systems')
    file_systems: List[Dict] = []
    for page in paginator.paginate():
        file_systems.extend(page.get('FileSystems', []))
    return file_systems


@timeit
def transform_efs_file_systems(file_systems: List[Dict]) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for fs in file_systems:
        arn = fs.get('FileSystemArn')
        if not arn:
            continue
        transformed.append({
            'FileSystemArn': arn,
            'FileSystemId': fs.get('FileSystemId'),
            'Name': fs.get('Name'),
            'CreationTime': dict_value_to_str(fs, 'CreationTime'),
            'Encrypted': fs.get('Encrypted'),
            'KmsKeyId': fs.get('KmsKeyId'),
            'LifeCycleState': fs.get('LifeCycleState'),
            'NumberOfMountTargets': fs.get('NumberOfMountTargets'),
            'consolelink': aws_console_link.get_console_link(arn=arn),
        })
    return transformed


@timeit
def load_efs_file_systems(
    neo4j_session: neo4j.Session, data: List[Dict[str, Any]], region: str, current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    logger.info(f"Loading {len(data)} EFS file systems for region '{region}' into graph.")
    load(
        neo4j_session,
        EFSFileSystemSchema(),
        data,
        lastupdated=aws_update_tag,
        Region=region,
        AWS_ID=current_aws_account_id,
    )


@timeit
def cleanup_efs(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    GraphJob.from_node_schema(EFSFileSystemSchema(), common_job_parameters).run(neo4j_session)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing EFS for account '%s', at %s.", current_aws_account_id, tic)

    for region in regions:
        logger.info("Syncing EFS for region '%s' in account '%s'.", region, current_aws_account_id)
        data = transform_efs_file_systems(get_efs_file_systems(boto3_session, region))
        load_efs_file_systems(neo4j_session, data, region, current_aws_account_id, update_tag)

    cleanup_efs(neo4j_session, common_job_parameters)
    merge_module_sync_metadata(
        neo4j_session,
        group_type='AWSAccount',
        group_id=current_aws_account_id,
        synced_type='EFSFileSystem',
        update_tag=update_tag,
        stat_handler=stat_handler,
    )

    toc = time.perf_counter()
    logger.info(f"Time to process EFS: {toc - tic:0.4f} seconds")
