import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_dms_replication_instances(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    instances: List[Dict] = []
    try:
        client = boto3_session.client('dms', region_name=region, config=get_botocore_config())
        paginator = client.get_paginator('describe_replication_instances')
        for page in paginator.paginate():
            instances.extend(page.get('ReplicationInstances', []))
    except ClientError as e:
        logger.warning(f"Failed to call DMS describe_replication_instances: {region} - {e}")
    return instances


@timeit
def transform_dms_replication_instances(instances: List[Dict], region: str) -> List[Dict]:
    transformed = []
    for instance in instances:
        instance['region'] = region
        instance['arn'] = instance.get('ReplicationInstanceArn')
        instance['consolelink'] = aws_console_link.get_console_link(arn=instance.get('ReplicationInstanceArn', ''))
        transformed.append(instance)
    return transformed


@timeit
def load_dms_replication_instances(
    neo4j_session: neo4j.Session, instances: List[Dict], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    query = """
    UNWIND $Instances as inst
    MERGE (n:DMSReplicationInstance{id: inst.arn})
    ON CREATE SET n.firstseen = timestamp(), n.arn = inst.arn
    SET n.lastupdated = $aws_update_tag,
        n.region = inst.region,
        n.consolelink = inst.consolelink,
        n.replication_instance_identifier = inst.ReplicationInstanceIdentifier,
        n.replication_instance_class = inst.ReplicationInstanceClass,
        n.engine_version = inst.EngineVersion,
        n.publicly_accessible = inst.PubliclyAccessible,
        n.auto_minor_version_upgrade = inst.AutoMinorVersionUpgrade,
        n.multi_az = inst.MultiAZ
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    neo4j_session.run(
        query, Instances=instances, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_dms_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
    current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing DMS for account '%s'.", current_aws_account_id)
    instances: List[Dict] = []
    for region in regions:
        instances.extend(
            transform_dms_replication_instances(
                get_dms_replication_instances(boto3_session, region), region,
            ),
        )
    load_dms_replication_instances(neo4j_session, instances, current_aws_account_id, update_tag)
    toc = time.perf_counter()
    logger.info(f"Time to process DMS: {toc - tic:0.4f} seconds")
