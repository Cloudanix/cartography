import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j

from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import aws_handle_regions
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
@aws_handle_regions
def get_ebs_encryption_by_default(boto3_session: boto3.session.Session, region: str) -> bool:
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    return bool(client.get_ebs_encryption_by_default().get('EbsEncryptionByDefault', False))


@timeit
def load_ebs_encryption_by_default(
    neo4j_session: neo4j.Session, settings: List[Dict], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    query = """
    UNWIND $Settings as s
    MERGE (n:EC2EbsEncryptionByDefault{id: s.id})
    ON CREATE SET n.firstseen = timestamp()
    SET n.lastupdated = $aws_update_tag,
        n.region = s.region,
        n.enabled = s.enabled
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    neo4j_session.run(query, Settings=settings, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag)


@timeit
def sync_ebs_encryption_by_default(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
    current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing EBS default encryption for account '%s'.", current_aws_account_id)
    settings: List[Dict] = []
    for region in regions:
        try:
            enabled = get_ebs_encryption_by_default(boto3_session, region)
        except Exception as e:
            logger.warning(f"Failed to get EBS default encryption for {region} - {e}")
            continue
        settings.append({
            "id": f"{current_aws_account_id}:{region}:ebs_encryption_by_default",
            "region": region,
            "enabled": enabled,
        })
    load_ebs_encryption_by_default(neo4j_session, settings, current_aws_account_id, update_tag)
    toc = time.perf_counter()
    logger.info(f"Time to process EBS default encryption: {toc - tic:0.4f} seconds")
