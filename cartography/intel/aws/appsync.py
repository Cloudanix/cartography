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
def get_graphql_apis(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    apis: List[Dict] = []
    try:
        client = boto3_session.client('appsync', region_name=region, config=get_botocore_config())
        paginator = client.get_paginator('list_graphql_apis')
        for page in paginator.paginate():
            apis.extend(page.get('graphqlApis', []))
    except ClientError as e:
        logger.warning(f"Failed to call appsync list_graphql_apis: {region} - {e}")
    for api in apis:
        api['region'] = region
        api['consolelink'] = aws_console_link.get_console_link(arn=api.get('arn', ''))
    return apis


@timeit
def load_graphql_apis(
    neo4j_session: neo4j.Session, apis: List[Dict], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    query = """
    UNWIND $Apis as api
    MERGE (n:AppSyncGraphqlApi{id: api.arn})
    ON CREATE SET n.firstseen = timestamp(), n.arn = api.arn
    SET n.lastupdated = $aws_update_tag,
        n.region = api.region,
        n.consolelink = api.consolelink,
        n.name = api.name,
        n.api_id = api.apiId,
        n.authentication_type = api.authenticationType,
        n.waf_web_acl_arn = api.wafWebAclArn
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    neo4j_session.run(query, Apis=apis, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
    current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing AppSync for account '%s'.", current_aws_account_id)
    apis: List[Dict] = []
    for region in regions:
        apis.extend(get_graphql_apis(boto3_session, region))
    load_graphql_apis(neo4j_session, apis, current_aws_account_id, update_tag)
    toc = time.perf_counter()
    logger.info(f"Time to process AppSync: {toc - tic:0.4f} seconds")
