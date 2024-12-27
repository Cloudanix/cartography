import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from .util import get_botocore_config
from cartography.graph.job import GraphJob
from cartography.models.aws.ec2.subnet_instance import EC2SubnetInstanceSchema
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit
logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_subnet_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    subnets = []
    try:

        paginator = client.get_paginator('describe_subnets')
        subnets: List[Dict] = []
        for page in paginator.paginate():
            subnets.extend(page['Subnets'])

        default_vpc = get_default_vpc(client)

        for subnet in subnets:
            if subnet.get('VpcId') != default_vpc('VpcId'):
                subnet['createdBy'] = 'user'
            else:
                subnet['createdBy'] = 'predefined'

            subnet['region'] = region
            subnet['consolelink'] = aws_console_link.get_console_link(arn=subnet['SubnetArn'])

    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException' or e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.warning(
                'ec2:describe_subnets failed with AccessDeniedException; continuing sync.',
                exc_info=True,
            )
        else:
            raise

    return subnets


@timeit
def get_default_vpc(ec2_client):
    try:
        response = ec2_client.describe_vpcs(
            Filters=[{'Name': 'isDefault', 'Values': ['true']}]
        )
        vpcs = response.get('Vpcs', [])

        if not vpcs:
            logger.info("No default VPC found.")
            return {}

        return vpcs[0]

    except Exception as e:
        logger.error(f"Error fetching default VPC: {e}")
        return {}


@timeit
def load_subnets(
    neo4j_session: neo4j.Session, data: List[Dict], aws_account_id: str,
    aws_update_tag: int,
) -> None:

    ingest_subnets = """
    UNWIND $subnets as subnet
    MERGE (snet:EC2Subnet{subnetid: subnet.SubnetId})
    ON CREATE SET snet.firstseen = timestamp()
    SET snet.lastupdated = $aws_update_tag, snet.name = subnet.CidrBlock, snet.cidr_block = subnet.CidrBlock,
    snet.available_ip_address_count = subnet.AvailableIpAddressCount, snet.default_for_az = subnet.DefaultForAz,
    snet.map_customer_owned_ip_on_launch = subnet.MapCustomerOwnedIpOnLaunch,snet.region = subnet.region,
    snet.state = subnet.State, snet.assignipv6addressoncreation = subnet.AssignIpv6AddressOnCreation,
    snet.map_public_ip_on_launch = subnet.MapPublicIpOnLaunch, snet.subnet_arn = subnet.SubnetArn,
    snet.availability_zone = subnet.AvailabilityZone, snet.availability_zone_id = subnet.AvailabilityZoneId,
    snet.subnetid = subnet.SubnetId, snet.arn = subnet.SubnetArn, snet.consolelink = subnet.consolelink,
    snet.created_by = subnet.createdBy
    """

    ingest_subnet_vpc_relations = """
    UNWIND $subnets as subnet
    MATCH (snet:EC2Subnet{subnetid: subnet.SubnetId}), (vpc:AWSVpc{id: subnet.VpcId})
    MERGE (snet)-[r:MEMBER_OF_AWS_VPC]->(vpc)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    ingest_subnet_aws_account_relations = """
    UNWIND $subnets as subnet
    MATCH (snet:EC2Subnet{subnetid: subnet.SubnetId}), (aws:AWSAccount{id: $aws_account_id})
    MERGE (aws)-[r:RESOURCE]->(snet)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    neo4j_session.run(
        ingest_subnets, subnets=data, aws_update_tag=aws_update_tag,
        aws_account_id=aws_account_id,
    )
    neo4j_session.run(
        ingest_subnet_vpc_relations, subnets=data, aws_update_tag=aws_update_tag,
        aws_account_id=aws_account_id,
    )
    neo4j_session.run(
        ingest_subnet_aws_account_relations, subnets=data, aws_update_tag=aws_update_tag,
        aws_account_id=aws_account_id,
    )


@timeit
def cleanup_subnets(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_ingest_subnets_cleanup.json', neo4j_session, common_job_parameters)
    GraphJob.from_node_schema(EC2SubnetInstanceSchema(), common_job_parameters).run(neo4j_session)


@timeit
def sync_subnets(
        neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
        current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing EC2 subnets for account '%s', at %s.", current_aws_account_id, tic)

    data = []
    for region in regions:
        logger.info("Syncing EC2 subnets for region '%s' in account '%s'.", region, current_aws_account_id)
        data.extend(get_subnet_data(boto3_session, region))

    logger.info(f"Total Subnets: {len(data)}")

    load_subnets(neo4j_session, data, current_aws_account_id, update_tag)
    cleanup_subnets(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process EC2 subnets: {toc - tic:0.4f} seconds")
