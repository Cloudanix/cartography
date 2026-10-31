import logging
import time
from typing import Any
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import EndpointConnectionError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_graphql_apis(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    """
    One paginated list_graphql_apis call per region; it already returns auth modes, WAF ACL and visibility,
    so no per-API describe is needed. Denials are skipped by aws_handle_regions; other errors propagate so the
    sync fails before the cleanup job would delete APIs of a region that was not read.
    """
    client = boto3_session.client('appsync', region_name=region, config=get_botocore_config())
    apis: List[Dict] = []
    try:
        for page in client.get_paginator('list_graphql_apis').paginate():
            apis.extend(page.get('graphqlApis', []))
    except EndpointConnectionError:
        # AppSync is not offered in every region.
        logger.warning(f"AppSync is not available in region {region}. Skipping.")
        return []
    return apis


@timeit
def transform_graphql_apis(apis: List[Dict], region: str) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for api in apis:
        arn = api.get('arn')
        if not arn:
            continue
        transformed.append({
            'arn': arn,
            'apiId': api.get('apiId'),
            'name': api.get('name'),
            'region': region,
            'consolelink': aws_console_link.get_console_link(arn=arn),
            'authenticationType': api.get('authenticationType'),
            'additionalAuthenticationTypes': [
                provider['authenticationType'] for provider in api.get('additionalAuthenticationProviders', [])
                if provider.get('authenticationType')
            ],
            'wafWebAclArn': api.get('wafWebAclArn'),
            # Absent on APIs created before private APIs existed; those are GLOBAL.
            'visibility': api.get('visibility', 'GLOBAL'),
            'apiType': api.get('apiType'),
            'xrayEnabled': api.get('xrayEnabled'),
            'logFieldLogLevel': api.get('logConfig', {}).get('fieldLogLevel'),
            'graphqlUri': api.get('uris', {}).get('GRAPHQL'),
        })
    return transformed


@timeit
def load_graphql_apis(
    neo4j_session: neo4j.Session, apis: List[Dict[str, Any]], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    # Label and the arn/api_id/name/waf_web_acl_arn/region/consolelink properties are read by the
    # aws-compliance-analyst-python SCHEDULED graph source (appsync_associated_with_waf); keep them stable.
    query = """
    UNWIND $DictList AS api
    MERGE (n:AppSyncGraphqlApi{id: api.arn})
    ON CREATE SET n.firstseen = timestamp(), n.arn = api.arn
    SET n.lastupdated = $aws_update_tag,
        n.name = api.name,
        n.api_id = api.apiId,
        n.region = api.region,
        n.consolelink = api.consolelink,
        n.authentication_type = api.authenticationType,
        n.additional_authentication_types = api.additionalAuthenticationTypes,
        n.waf_web_acl_arn = api.wafWebAclArn,
        n.visibility = api.visibility,
        n.api_type = api.apiType,
        n.xray_enabled = api.xrayEnabled,
        n.log_field_log_level = api.logFieldLogLevel,
        n.graphql_uri = api.graphqlUri
    WITH n
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(n)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """
    load_graph_data(
        neo4j_session, query, apis, AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup_graphql_apis(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_appsync_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing AppSync for account '%s', at %s.", current_aws_account_id, tic)

    apis: List[Dict[str, Any]] = []
    for region in regions:
        logger.info("Syncing AppSync for region '%s' in account '%s'.", region, current_aws_account_id)
        apis.extend(transform_graphql_apis(get_graphql_apis(boto3_session, region), region))

    logger.info(f"Total AppSync GraphQL APIs: {len(apis)}")
    load_graphql_apis(neo4j_session, apis, current_aws_account_id, update_tag)
    cleanup_graphql_apis(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process AppSync: {toc - tic:0.4f} seconds")
