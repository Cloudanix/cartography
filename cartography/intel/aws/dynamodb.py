import logging
from typing import Dict
from typing import List

import boto3
import neo4j

import time
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit
from cloudconsolelink.clouds.aws import AWS

logger = logging.getLogger(__name__)
aws_console_link = AWS()


@timeit
@aws_handle_regions
def get_dynamodb_tables(boto3_session: boto3.session.Session, region: str, common_job_parameters) -> List[Dict]:
    client = boto3_session.client('dynamodb', region_name=region)
    paginator = client.get_paginator('list_tables')
    dynamodb_tables = []
    for page in paginator.paginate():
        for table_name in page['TableNames']:
            dynamodb_tables.append(client.describe_table(TableName=table_name))

    if common_job_parameters.get('pagination', {}).get('dynamodb', None):
        page_start = (common_job_parameters.get('pagination', {}).get('dynamodb', {})[
                      'pageNo'] - 1) * common_job_parameters.get('pagination', {}).get('dynamodb', {})['pageSize']
        page_end = page_start + common_job_parameters.get('pagination', {}).get('dynamodb', {})['pageSize']
        if page_end > len(dynamodb_tables) or page_end == len(dynamodb_tables):
            dynamodb_tables = dynamodb_tables[page_start:]
        else:
            has_next_page = True
            dynamodb_tables = dynamodb_tables[page_start:page_end]
            common_job_parameters['pagination']['dynamodb']['has_next_page'] = has_next_page

    return dynamodb_tables


@timeit
def load_dynamodb_tables(
    neo4j_session: neo4j.Session, data: List[Dict], region: str, current_aws_account_id: str,
    aws_update_tag: str,
) -> None:
    ingest_table = """
    MERGE (table:DynamoDBTable{id: {Arn}})
    ON CREATE SET table.firstseen = timestamp(), table.arn = {Arn}, table.name = {TableName},
    table.consolelink = {consolelink},
    table.region = {Region}
    SET table.lastupdated = {aws_update_tag}, table.rows = {Rows}, table.size = {Size},
    table.provisioned_throughput_read_capacity_units = {ProvisionedThroughputReadCapacityUnits},
    table.provisioned_throughput_write_capacity_units = {ProvisionedThroughputWriteCapacityUnits}
    WITH table
    MATCH (owner:AWSAccount{id: {AWS_ACCOUNT_ID}})
    MERGE (owner)-[r:RESOURCE]->(table)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for table in data:
        neo4j_session.run(
            ingest_table,
            Arn=table['Table']['TableArn'],
            consolelink=aws_console_link.get_console_link(arn=table['Table']['TableArn']),
            Region=region,
            ProvisionedThroughputReadCapacityUnits=table['Table']['ProvisionedThroughput']['ReadCapacityUnits'],
            ProvisionedThroughputWriteCapacityUnits=table['Table']['ProvisionedThroughput']['WriteCapacityUnits'],
            Size=table['Table']['TableSizeBytes'],
            TableName=table['Table']['TableName'],
            Rows=table['Table']['ItemCount'],
            AWS_ACCOUNT_ID=current_aws_account_id,
            aws_update_tag=aws_update_tag,
        )
        load_gsi(neo4j_session, table, region, current_aws_account_id, aws_update_tag)


@timeit
def load_gsi(
    neo4j_session: neo4j.Session, table: Dict, region: str, current_aws_account_id: str,
    aws_update_tag: str,
) -> None:
    ingest_gsi = """
    MERGE (gsi:DynamoDBGlobalSecondaryIndex{id: {Arn}})
    ON CREATE SET gsi.firstseen = timestamp(), gsi.arn = {Arn}, gsi.name = {GSIName},
    gsi.region = {Region}
    SET gsi.lastupdated = {aws_update_tag},
    gsi.provisioned_throughput_read_capacity_units = {ProvisionedThroughputReadCapacityUnits},
    gsi.provisioned_throughput_write_capacity_units = {ProvisionedThroughputWriteCapacityUnits}
    WITH gsi
    MATCH (table:DynamoDBTable{arn: {TableArn}})
    MERGE (table)-[r:GLOBAL_SECONDARY_INDEX]->(gsi)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {aws_update_tag}
    """

    for gsi in table['Table'].get('GlobalSecondaryIndexes', []):
        neo4j_session.run(
            ingest_gsi,
            TableArn=table['Table']['TableArn'],
            Arn=gsi['IndexArn'],
            Region=region,
            ProvisionedThroughputReadCapacityUnits=gsi['ProvisionedThroughput']['ReadCapacityUnits'],
            ProvisionedThroughputWriteCapacityUnits=gsi['ProvisionedThroughput']['WriteCapacityUnits'],
            GSIName=gsi['IndexName'],
            AWS_ACCOUNT_ID=current_aws_account_id,
            aws_update_tag=aws_update_tag,
        )


@timeit
def cleanup_dynamodb_tables(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_dynamodb_tables_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_dynamodb_tables(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    aws_update_tag: int, common_job_parameters: Dict,
) -> None:
    for region in regions:
        logger.info("Syncing DynamoDB for region in '%s' in account '%s'.", region, current_aws_account_id)
        data = get_dynamodb_tables(boto3_session, region, common_job_parameters)
        load_dynamodb_tables(neo4j_session, data, region, current_aws_account_id, aws_update_tag)
    cleanup_dynamodb_tables(neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing DynamoDB for account '%s', at %s.", current_aws_account_id, tic)

    sync_dynamodb_tables(
        neo4j_session, boto3_session, regions, current_aws_account_id, update_tag, common_job_parameters,
    )

    toc = time.perf_counter()
    print(f"Total Time to process DynamoDB: {toc - tic:0.4f} seconds")
