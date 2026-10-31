import logging
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load
from cartography.graph.job import GraphJob
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.models.aws.fsx.filesystems import FSxFileSystemSchema
from cartography.util import aws_handle_regions
from cartography.util import dict_value_to_iso
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()

# Each file system type carries its settings, including native automatic backups, in its own block.
TYPE_CONFIGURATION_KEYS = (
    'WindowsConfiguration', 'LustreConfiguration', 'OntapConfiguration', 'OpenZFSConfiguration',
)


@timeit
@aws_handle_regions
def get_fsx_file_systems(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('fsx', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_file_systems')
    file_systems: List[Dict] = []
    for page in paginator.paginate():
        file_systems.extend(page.get('FileSystems', []))
    return file_systems


def _automatic_backup_retention_days(fs: Dict) -> Optional[int]:
    for key in TYPE_CONFIGURATION_KEYS:
        days = (fs.get(key) or {}).get('AutomaticBackupRetentionDays')
        if days is not None:
            return days
    return None


def transform_fsx_file_systems(file_systems: List[Dict]) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for fs in file_systems:
        arn = fs.get('ResourceARN')
        if not arn:
            continue
        transformed.append({
            'ResourceARN': arn,
            'FileSystemId': fs.get('FileSystemId'),
            'FileSystemType': fs.get('FileSystemType'),
            'CreationTime': dict_value_to_iso(fs, 'CreationTime'),
            'Lifecycle': fs.get('Lifecycle'),
            'KmsKeyId': fs.get('KmsKeyId'),
            'StorageCapacity': fs.get('StorageCapacity'),
            'StorageType': fs.get('StorageType'),
            'DNSName': fs.get('DNSName'),
            'VpcId': fs.get('VpcId'),
            'SubnetIds': fs.get('SubnetIds'),
            'AutomaticBackupRetentionDays': _automatic_backup_retention_days(fs),
            'consolelink': aws_console_link.get_console_link(arn=arn),
        })
    return transformed


@timeit
def load_fsx_file_systems(
    neo4j_session: neo4j.Session,
    data: List[Dict[str, Any]],
    region: str,
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    logger.info(f"Loading {len(data)} FSx file systems for region '{region}' into graph.")
    load(
        neo4j_session,
        FSxFileSystemSchema(),
        data,
        lastupdated=aws_update_tag,
        Region=region,
        AWS_ID=current_aws_account_id,
    )


@timeit
def cleanup_fsx(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    GraphJob.from_node_schema(FSxFileSystemSchema(), common_job_parameters).run(neo4j_session)


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
    logger.info("Syncing FSx for account '%s', at %s.", current_aws_account_id, tic)

    for region in regions:
        logger.info("Syncing FSx for region '%s' in account '%s'.", region, current_aws_account_id)
        data = transform_fsx_file_systems(get_fsx_file_systems(boto3_session, region))
        load_fsx_file_systems(neo4j_session, data, region, current_aws_account_id, update_tag)

    cleanup_fsx(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process FSx: {toc - tic:0.4f} seconds")
