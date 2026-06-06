import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j

from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_macie_session(boto3_session: boto3.session.Session, region: str) -> Dict:
    """GetMacieSession for a region. Empty dict when Macie is not enabled (opt-in/unused region)
    or on access error — the absence then reads as "not synced for this region"."""
    try:
        client = boto3_session.client('macie2', region_name=region, config=get_botocore_config())
        return client.get_macie_session()
    except Exception as e:
        logger.debug(f"Unable to fetch Macie session for {region} - {e}")
        return {}


@timeit
def load_macie_sessions(
    neo4j_session: neo4j.Session, sessions: List[Dict], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    query = """
    UNWIND $Sessions as s
    MERGE (n:AWSMacieSession{id: s.id})
    ON CREATE SET n.firstseen = timestamp()
    SET n.lastupdated = $aws_update_tag,
        n.region = s.region,
        n.status = s.status,
        n.finding_publishing_frequency = s.finding_publishing_frequency
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    neo4j_session.run(
        query, Sessions=sessions, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag,
    )


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
    current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing Macie for account '%s'.", current_aws_account_id)
    sessions: List[Dict] = []
    for region in regions:
        response = get_macie_session(boto3_session, region)
        if not response or not response.get('status'):
            continue  # not enabled / unsynced region -> no node (reads as skip downstream)
        sessions.append({
            'id': f"{current_aws_account_id}:{region}:macie",
            'region': region,
            'status': response.get('status'),
            'finding_publishing_frequency': response.get('findingPublishingFrequency'),
        })
    load_macie_sessions(neo4j_session, sessions, current_aws_account_id, update_tag)
    toc = time.perf_counter()
    logger.info(f"Time to process Macie: {toc - tic:0.4f} seconds")
