import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.intel.aws.util.arns import DEFAULT_PARTITION
from cartography.intel.aws.util.arns import get_partition_from_params
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()

# Applied at describe_snapshots so pending/error never leave the API. Ownership goes in OwnerIds: the
# owner-alias filter only knows Amazon-maintained aliases ('amazon'), not 'self'.
EBS_SNAPSHOT_FILTERS = [
    {
        "Name": "status",
        "Values": ["completed"],
    },
]


@timeit
@aws_handle_regions
def get_snapshots(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    """
    The account's own completed snapshots. volume_permissions is ['all'] for a public snapshot (create volume
    permission granted to the 'all' group), else []. One extra paginated call finds the public ones
    (RestorableByUserIds=['all']) instead of a describe_snapshot_attribute call per snapshot.
    """
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    snapshots: List[Dict] = []
    try:
        paginator = client.get_paginator('describe_snapshots')
        for page in paginator.paginate(OwnerIds=['self'], Filters=EBS_SNAPSHOT_FILTERS):
            snapshots.extend(page['Snapshots'])
        public_ids = {
            snapshot['SnapshotId']
            for page in paginator.paginate(OwnerIds=['self'], RestorableByUserIds=['all'])
            for snapshot in page['Snapshots']
        }
        for snapshot in snapshots:
            snapshot['region'] = region
            snapshot['volume_permissions'] = ['all'] if snapshot['SnapshotId'] in public_ids else []

    except ClientError as e:
        if e.response['Error']['Code'] in ('AccessDeniedException', 'UnauthorizedOperation'):
            logger.warning(
                'ec2:describe_snapshots failed with AccessDeniedException; continuing sync.',
                exc_info=True,
            )
        else:
            raise

    return snapshots


@timeit
def load_snapshots(
        neo4j_session: neo4j.Session, data: List[Dict], current_aws_account_id: str, update_tag: int,
        partition: str = DEFAULT_PARTITION,
) -> None:
    ingest_snapshots = """
    UNWIND $DictList as snapshot
    MERGE (s:EBSSnapshot{id: snapshot.SnapshotId})
    ON CREATE SET s.firstseen = timestamp()
    SET s.lastupdated = $update_tag, s.description = snapshot.Description, s.encrypted = snapshot.Encrypted,
    s.progress = snapshot.Progress, s.starttime = snapshot.StartTime, s.state = snapshot.State, s.consolelink = snapshot.consolelink,
    s.statemessage = snapshot.StateMessage, s.volumeid = snapshot.VolumeId, s.volumesize = snapshot.VolumeSize,
    s.outpostarn = snapshot.OutpostArn, s.dataencryptionkeyid = snapshot.DataEncryptionKeyId,
    s.kmskeyid = snapshot.KmsKeyId, s.region = snapshot.region, s.arn = snapshot.Arn,s.volume_permissions=snapshot.volume_permissions
    WITH s
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(s)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    # neo4j does not accept datetime objects and values. This loop is used to convert
    # these values to string.
    for snapshot in data:
        region = snapshot.get('region', '')
        snapshot['StartTime'] = str(snapshot['StartTime'])
        snapshot['Arn'] = f"arn:{partition}:ec2:{region}:{current_aws_account_id}:snapshot/{snapshot['SnapshotId']}"
        snapshot['consolelink'] = aws_console_link.get_console_link(arn=snapshot['Arn'])

    load_graph_data(
        neo4j_session,
        ingest_snapshots,
        data,
        AWS_ACCOUNT_ID=current_aws_account_id,
        update_tag=update_tag,
    )


@timeit
def get_snapshot_volumes(snapshots: List[Dict]) -> List[Dict]:
    snapshot_volumes: List[Dict] = []
    for snapshot in snapshots:
        if snapshot.get('VolumeId'):
            snapshot_volumes.append(snapshot)

    return snapshot_volumes


@timeit
def load_snapshot_volume_relations(
        neo4j_session: neo4j.Session, data: List[Dict], current_aws_account_id: str, update_tag: int,
) -> None:
    ingest_volumes = """
    UNWIND $DictList as volume
    MERGE (v:EBSVolume{id: volume.VolumeId})
    ON CREATE SET v.firstseen = timestamp()
    SET v.lastupdated = $update_tag
    WITH v, volume
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(v)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH v, volume
    MATCH (s:EBSSnapshot{id: volume.SnapshotId})
    MERGE (s)-[r:CREATED_FROM]->(v)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    load_graph_data(
        neo4j_session,
        ingest_volumes,
        data,
        AWS_ACCOUNT_ID=current_aws_account_id,
        update_tag=update_tag,
    )


@timeit
def cleanup_snapshots(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job(
        'aws_import_snapshots_cleanup.json',
        neo4j_session,
        common_job_parameters,
    )


@timeit
def sync_ebs_snapshots(
        neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
        current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing Snapshots for account '%s', at %s.", current_aws_account_id, tic)

    data = []
    for region in regions:
        logger.debug("Syncing snapshots for region '%s' in account '%s'.", region, current_aws_account_id)
        data.extend(get_snapshots(boto3_session, region))

    logger.info(f"Total EBS Snapshot: {len(data)}")

    load_snapshots(
        neo4j_session, data, current_aws_account_id, update_tag,
        partition=get_partition_from_params(common_job_parameters),
    )

    snapshot_volumes = get_snapshot_volumes(data)

    logger.info(f"Total EBS Volumes: {len(snapshot_volumes)}")

    load_snapshot_volume_relations(neo4j_session, snapshot_volumes, current_aws_account_id, update_tag)
    cleanup_snapshots(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Snapshots: {toc - tic:0.4f} seconds")
