import logging
import time
from typing import *
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_waf_classic_web_acls(boto3_session: boto3.session.Session) -> List[Dict]:

    web_acls = []
    try:
        client = boto3_session.client('waf')
        paginator = client.get_paginator('list_web_acls')

        page_iterator = paginator.paginate()
        for page in page_iterator:
            web_acls.extend(page.get('WebACLs', []))

        return web_acls

    except ClientError as e:
        logger.error(f'Failed to call WAF Classic list_web_acls: {e}')
        return web_acls


@timeit
def get_waf_classic_details(boto3_session: boto3.session.Session, web_acl_id: str) -> Dict:
    response = {}
    try:
        client = boto3_session.client('waf')
        response = client.get_web_acl(WebACLId=web_acl_id)
    except ClientError as e:
        logger.error(f"Error retrieving Web ACL {web_acl_id}: {e}")

    return response.get("WebACL", {})


@timeit
def transform_waf_classic_web_acls(boto3_session: boto3.session.Session, web_acls: List[Dict]) -> List[Dict]:
    transformed_acls = []
    for web_acl in web_acls:
        web_acl_id = web_acl.get("WebACLId")
        details = get_waf_classic_details(boto3_session, web_acl_id)
        arn = details.get("WebACLArn")

        web_acl['region'] = 'global'
        web_acl['consolelink'] = ""
        web_acl['arn'] = arn
        #web_acl['consolelink'] = aws_console_link.get_console_link(arn=web_acl['arn'])
        transformed_acls.append(web_acl)

    return transformed_acls


def load_waf_classic_web_acls(session: neo4j.Session, web_acls: List[Dict], current_aws_account_id: str, aws_update_tag: int) -> None:
    session.write_transaction(_load_waf_classic_web_acls_tx, web_acls, current_aws_account_id, aws_update_tag)


@timeit
def _load_waf_classic_web_acls_tx(tx: neo4j.Transaction, web_acls: List[Dict], current_aws_account_id: str, aws_update_tag: int) -> None:
    query: str = """
    UNWIND $Records as record
    MERGE (web_acl:AWSWAFClassicWebACL{id: record.arn})
    ON CREATE SET web_acl.firstseen = timestamp(),
        web_acl.arn = record.arn
    SET web_acl.lastupdated = $aws_update_tag,
        web_acl.name = record.Name,
        web_acl.region = record.region,
        web_acl.consolelink = record.consolelink
    WITH web_acl
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(web_acl)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        query,
        Records=web_acls,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup_waf_classic_web_acls(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_waf_classic_web_acls_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_waf_classic(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    web_acls = get_waf_classic_web_acls(boto3_session)
    transformed_acls = transform_waf_classic_web_acls(boto3_session, web_acls)

    logger.info(f"Total WAF Classic WebACLs: {len(transformed_acls)}")

    load_waf_classic_web_acls(neo4j_session, transformed_acls, current_aws_account_id, update_tag)

    cleanup_waf_classic_web_acls(neo4j_session, common_job_parameters)


@timeit
def get_waf_v2_web_acl_details(
    client: boto3.client, acl: Dict, scope: str, region: str
) -> Dict:
    """
    Get detailed information about a WAFv2 Web ACL
    """
    try:
        response = client.get_web_acl(Name=acl["Name"], Scope=scope, Id=acl["Id"])
        acl_details = response.get("WebACL", {})

        return {
            "Name": acl.get("Name", ""),
            "Id": acl.get("Id", ""),
            "ARN": acl.get("ARN", ""),
            "region": region,
            "scope": scope,
            "default_action": acl_details.get("DefaultAction", {}).get("Type", ""),
            "rules_count": str(len(acl_details.get("Rules", []))),
            "capacity": str(acl_details.get("Capacity", 0))
        }
    except ClientError as e:
        logger.error(
            f'Failed to get WAF ACL details for {acl.get("Name", "Unknown")}: {e}'
        )
        return {}


@timeit
def get_waf_v2_web_acls_for_scope(
    client: boto3.client, scope: str, region: str
) -> List[Dict]:
    """
    Get WAFv2 Web ACLs for a specific scope.
    """
    web_acls = []
    response = {}
    try:
        response = client.list_web_acls(Scope=scope)
        for acl in response.get("WebACLs", []):
            acl_with_details = get_waf_v2_web_acl_details(client, acl, scope, region)
            if acl_with_details:
                web_acls.append(acl_with_details)

    except ClientError as e:
        logger.error(f"Failed to call WAF v2 list_web_acls for scope {scope}: {e}")
        return web_acls

    while "NextMarker" in response:
        try:
            response = client.list_web_acls(
                Scope=scope,
                NextMarker=response["NextMarker"],
            )
            for acl in response.get("WebACLs", []):
                acl_with_details = get_waf_v2_web_acl_details(
                    client, acl, scope, region
                )
                if acl_with_details:
                    web_acls.append(acl_with_details)

        except ClientError as e:
            logger.error(f"Failed to call WAF v2 list_web_acls - next page: {e}")
            break

    return web_acls


@timeit
@aws_handle_regions
def get_waf_v2_web_acls(boto3_session: boto3.session.Session) -> List[Dict]:
    """Get all WAFv2 Web ACLs (both CloudFront and Regional).
    Args:
        boto3_session: Boto3 session
    Returns:
        List[Dict]: Combined list of global and regional WAF ACLs
    """
    web_acls = []
    try:
        # CloudFront (Global) ACLs - requires us-east-1
        client = boto3_session.client("wafv2", region_name="us-east-1")
        web_acls.extend(get_waf_v2_web_acls_for_scope(client, "CLOUDFRONT", "global"))

        # Regional ACLs
        regional_client = boto3_session.client("wafv2")
        web_acls.extend(
            get_waf_v2_web_acls_for_scope(
                regional_client, "REGIONAL", boto3_session.region_name
            )
        )

    except ClientError as e:
        logger.error(f"Failed to get WAFv2 web ACLs: {e}")

    return web_acls


@timeit
def transform_waf_v2_web_acls(web_acls: List[Dict]) -> List[Dict]:
    transformed_acls = []
    for web_acl in web_acls:
        web_acl["arn"] = web_acl["ARN"]
        web_acl["consolelink"] = ""
        # web_acl['consolelink'] = aws_console_link.get_console_link(arn=web_acl['arn'])
        transformed_acls.append(web_acl)
    return transformed_acls


def load_waf_v2_web_acls(session: neo4j.Session, web_acls: List[Dict], current_aws_account_id: str, aws_update_tag: int) -> None:
    session.write_transaction(_load_waf_v2_web_acls_tx, web_acls, current_aws_account_id, aws_update_tag)


@timeit
def _load_waf_v2_web_acls_tx(tx: neo4j.Transaction, web_acls: List[Dict], current_aws_account_id: str, aws_update_tag: int) -> None:
    query: str = """
    UNWIND $Records as record
    MERGE (web_acl:AWSWAFv2WebACL{id: record.arn})
    ON CREATE SET web_acl.firstseen = timestamp(),
        web_acl.arn = record.arn
    SET web_acl.lastupdated = $aws_update_tag,
        web_acl.name = record.Name,
        web_acl.region = record.region,
        web_acl.consolelink = record.consolelink,
        web_acl.scope = record.scope,
        web_acl.default_action = record.default_action,
        web_acl.rules_count = record.rules_count,
        web_acl.capacity = record.capacity
    WITH web_acl
    MATCH (owner:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (owner)-[r:RESOURCE]->(web_acl)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        query,
        Records=web_acls,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup_waf_v2_web_acls(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_waf_v2_web_acls_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_waf_v2(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    web_acls = get_waf_v2_web_acls(boto3_session)
    transformed_acls = transform_waf_v2_web_acls(web_acls)

    logger.info(f"Total WAF v2 WebACLs: {len(transformed_acls)}")

    load_waf_v2_web_acls(neo4j_session, transformed_acls, current_aws_account_id, update_tag)

    cleanup_waf_v2_web_acls(neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing WAF for account '%s', at %s.", current_aws_account_id, tic)

    try:
        sync_waf_classic(neo4j_session, boto3_session, current_aws_account_id, update_tag, common_job_parameters)

        sync_waf_v2(neo4j_session, boto3_session, current_aws_account_id, update_tag, common_job_parameters)

    except Exception as ex:
        logger.error("failed to process waf", ex)

    toc = time.perf_counter()
    logger.info(f"Time to process WAF: {toc - tic:0.4f} seconds")
