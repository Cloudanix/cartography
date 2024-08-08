import logging
import time
from typing import Dict, List
from typing import *

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
def transform_waf_classic_web_acls(web_acls: List[Dict]) -> List[Dict]:
    transformed_acls = []
    for web_acl in web_acls:
        web_acl['region'] = 'global'
        web_acl['arn'] = web_acl['ARN']
        web_acl['consolelink'] = aws_console_link.get_console_link(arn=web_acl['arn'])
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
    tic = time.perf_counter()

    logger.info("Syncing WAF Classic for account '%s', at %s.", current_aws_account_id, tic)

    web_acls = get_waf_classic_web_acls(boto3_session)
    transformed_acls = transform_waf_classic_web_acls(web_acls)

    logger.info(f"Total WAF Classic WebACLs: {len(transformed_acls)}")

    load_waf_classic_web_acls(neo4j_session, transformed_acls, current_aws_account_id, update_tag)

    cleanup_waf_classic_web_acls(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process WAF Classic: {toc - tic:0.4f} seconds")


@timeit
@aws_handle_regions
def get_waf_v2_web_acls(boto3_session: boto3.session.Session) -> List[Dict]:
    web_acls = []
    try:
        client = boto3_session.client('wafv2')
        paginator = client.get_paginator('list_web_acls')

        page_iterator = paginator.paginate(Scope='CLOUDFRONT')
        for page in page_iterator:
            web_acls.extend(page.get('WebACLs', []))

        return web_acls

    except ClientError as e:
        logger.error(f'Failed to call WAF v2 list_web_acls: {e}')
        return web_acls


@timeit
def transform_waf_v2_web_acls(web_acls: List[Dict]) -> List[Dict]:
    transformed_acls = []
    for web_acl in web_acls:
        web_acl['region'] = 'global'
        web_acl['arn'] = web_acl['ARN']
        web_acl['consolelink'] = aws_console_link.get_console_link(arn=web_acl['arn'])
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
def cleanup_waf_v2_web_acls(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_waf_v2_web_acls_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_waf_v2(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing WAF v2 for account '%s', at %s.", current_aws_account_id, tic)

    web_acls = get_waf_v2_web_acls(boto3_session)
    transformed_acls = transform_waf_v2_web_acls(web_acls)

    logger.info(f"Total WAF v2 WebACLs: {len(transformed_acls)}")

    load_waf_v2_web_acls(neo4j_session, transformed_acls, current_aws_account_id, update_tag)

    cleanup_waf_v2_web_acls(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process WAF v2: {toc - tic:0.4f} seconds")
