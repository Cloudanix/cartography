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
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_firehose_delivery_streams(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    streams: List[Dict] = []
    try:
        client = boto3_session.client('firehose', region_name=region, config=get_botocore_config())
        names: List[str] = []
        response = client.list_delivery_streams()
        names.extend(response.get('DeliveryStreamNames', []))
        while response.get('HasMoreDeliveryStreams'):
            response = client.list_delivery_streams(
                ExclusiveStartDeliveryStreamName=names[-1],
            )
            names.extend(response.get('DeliveryStreamNames', []))
        for name in names:
            try:
                desc = client.describe_delivery_stream(
                    DeliveryStreamName=name,
                ).get('DeliveryStreamDescription', {})
            except ClientError as e:
                logger.warning(f"Failed to describe firehose stream {name} - {e}")
                desc = {}
            arn = desc.get('DeliveryStreamARN') or f"arn:aws:firehose:{region}::deliverystream/{name}"
            enc = desc.get('DeliveryStreamEncryptionConfiguration', {}) or {}
            streams.append({
                'arn': arn,
                'name': name,
                'region': region,
                'consolelink': aws_console_link.get_console_link(arn=arn),
                'sse_status': enc.get('Status'),
                'key_type': enc.get('KeyType'),
                'key_arn': enc.get('KeyARN'),
            })
    except ClientError as e:
        logger.warning(f"Failed to call firehose list_delivery_streams: {region} - {e}")
    return streams


@timeit
def load_firehose_delivery_streams(
    neo4j_session: neo4j.Session, streams: List[Dict], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    query = """
    UNWIND $Streams as s
    MERGE (n:FirehoseDeliveryStream{id: s.arn})
    ON CREATE SET n.firstseen = timestamp(), n.arn = s.arn
    SET n.lastupdated = $aws_update_tag,
        n.name = s.name,
        n.region = s.region,
        n.consolelink = s.consolelink,
        n.sse_status = s.sse_status,
        n.key_type = s.key_type,
        n.key_arn = s.key_arn
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    neo4j_session.run(query, Streams=streams, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
    current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing Firehose for account '%s'.", current_aws_account_id)
    streams: List[Dict] = []
    for region in regions:
        streams.extend(get_firehose_delivery_streams(boto3_session, region))
    load_firehose_delivery_streams(neo4j_session, streams, current_aws_account_id, update_tag)
    toc = time.perf_counter()
    logger.info(f"Time to process Firehose: {toc - tic:0.4f} seconds")
