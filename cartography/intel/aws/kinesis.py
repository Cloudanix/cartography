import logging
import time
from typing import Any
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load
from cartography.graph.job import GraphJob
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.models.aws.kinesis.streams import KinesisStreamSchema
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_kinesis_streams(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    """
    Fetch all Kinesis streams and their details for a given region.
    """
    client = boto3_session.client('kinesis', region_name=region, config=get_botocore_config())
    streams: List[Dict] = []

    try:
        paginator = client.get_paginator('list_streams')
        for page in paginator.paginate():
            for stream_summary in page.get('StreamSummaries', []):
                stream_name = stream_summary['StreamName']
                try:
                    stream_detail = client.describe_stream_summary(StreamName=stream_name)
                    stream_desc = stream_detail.get('StreamDescriptionSummary', {})
                    streams.append(stream_desc)
                except ClientError as e:
                    logger.warning(
                        f"Failed to describe Kinesis stream {stream_name} in {region}: {e}",
                    )
                    continue
    except ClientError as e:
        logger.warning(f"Failed to list Kinesis streams in {region}: {e}")

    return streams


@timeit
def transform_kinesis_streams(
    streams: List[Dict], region: str, current_aws_account_id: str,
) -> List[Dict[str, Any]]:
    """
    Transform raw Kinesis stream data into the format expected by the graph schema.
    """
    transformed: List[Dict[str, Any]] = []

    for stream in streams:
        stream_arn = stream.get('StreamARN', '')
        stream_mode_details = stream.get('StreamModeDetails', {})
        stream_mode = stream_mode_details.get('StreamMode', 'PROVISIONED')

        creation_timestamp = stream.get('StreamCreationTimestamp')
        if creation_timestamp:
            creation_timestamp = str(creation_timestamp)

        transformed.append({
            'StreamARN': stream_arn,
            'StreamName': stream.get('StreamName', ''),
            'StreamStatus': stream.get('StreamStatus', ''),
            'StreamMode': stream_mode,
            'RetentionPeriodHours': stream.get('RetentionPeriodHours'),
            'OpenShardCount': stream.get('OpenShardCount'),
            'EncryptionType': stream.get('EncryptionType', 'NONE'),
            'Encrypted': stream.get('EncryptionType', 'NONE') != 'NONE',
            'KeyId': stream.get('KeyId'),
            'StreamCreationTimestamp': creation_timestamp,
            'consolelink': aws_console_link.get_console_link(arn=stream_arn),
            'Region': region,
        })

    return transformed


@timeit
def load_kinesis_streams(
    neo4j_session: neo4j.Session,
    stream_data: List[Dict[str, Any]],
    region: str,
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    logger.info(f"Loading {len(stream_data)} Kinesis streams for region '{region}' into graph.")
    load(
        neo4j_session,
        KinesisStreamSchema(),
        stream_data,
        lastupdated=aws_update_tag,
        Region=region,
        AWS_ID=current_aws_account_id,
    )


@timeit
def cleanup_kinesis_streams(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    GraphJob.from_node_schema(KinesisStreamSchema(), common_job_parameters).run(neo4j_session)


@timeit
def sync_kinesis_streams(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    regions: List[str],
    current_aws_account_id: str,
    aws_update_tag: int,
    common_job_parameters: Dict,
) -> None:
    for region in regions:
        logger.info("Syncing Kinesis streams for region '%s' in account '%s'.", region, current_aws_account_id)
        raw_streams = get_kinesis_streams(boto3_session, region)
        stream_data = transform_kinesis_streams(raw_streams, region, current_aws_account_id)
        load_kinesis_streams(neo4j_session, stream_data, region, current_aws_account_id, aws_update_tag)

    cleanup_kinesis_streams(neo4j_session, common_job_parameters)


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

    logger.info("Syncing Kinesis for account '%s', at %s.", current_aws_account_id, tic)

    sync_kinesis_streams(
        neo4j_session, boto3_session, regions, current_aws_account_id, update_tag, common_job_parameters,
    )

    toc = time.perf_counter()
    logger.info(f"Time to process Kinesis: {toc - tic:0.4f} seconds")
