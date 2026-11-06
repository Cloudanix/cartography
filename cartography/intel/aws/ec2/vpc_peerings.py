import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from .util import get_botocore_config
from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.util.arns import DEFAULT_PARTITION
from cartography.intel.aws.util.arns import get_partition_from_params
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_vpc_peerings_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    vpc_peerings = []
    try:
        client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
        vpc_peerings = client.describe_vpc_peering_connections()['VpcPeeringConnections']

    except Exception as e:
        logger.warning(f"Failed retrieve VPC Peerings for region - {region}. Error - {e}")

    return vpc_peerings


@timeit
def load_vpc_peerings(
    neo4j_session: neo4j.Session, data: List[Dict], region: str,
    aws_account_id: str, update_tag: int, workspace_id: str, partition: str = DEFAULT_PARTITION,
) -> None:
    ingest_vpc_peerings = """
    UNWIND $DictList AS vpc_peering
    // organizations.sync creates the account first; without it, write nothing.
    MATCH (account:AWSAccount{id: $aws_account_id})

    // Both sides' accounts report the same peering id, and the other side may be another customer:
    // each account claims its own node, never one another tenant wrote.
    MERGE (account)-[res:RESOURCE]->(pcx:AWSPeeringConnection{id: vpc_peering.VpcPeeringConnectionId})
    ON CREATE SET pcx.firstseen = timestamp(), res.firstseen = timestamp()
    SET res.lastupdated = $update_tag,
    pcx.lastupdated = $update_tag,
    pcx.accepter_vpc_id = vpc_peering.AccepterVpcInfo.VpcId,
    pcx.accepter_owner_id = vpc_peering.AccepterVpcInfo.OwnerId,
    pcx.accepter_cidr_blocks = [c IN coalesce(vpc_peering.AccepterVpcInfo.CidrBlockSet, []) | c.CidrBlock],
    pcx.requester_vpc_id = vpc_peering.RequesterVpcInfo.VpcId,
    pcx.requester_owner_id = vpc_peering.RequesterVpcInfo.OwnerId,
    pcx.requester_cidr_blocks = [c IN coalesce(vpc_peering.RequesterVpcInfo.CidrBlockSet, []) | c.CidrBlock],
    pcx.allow_dns_resolution_from_remote_vpc =
        vpc_peering.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc,
    pcx.allow_egress_from_local_classic_link_to_remote_vpc =
        vpc_peering.RequesterVpcInfo.PeeringOptions.AllowEgressFromLocalClassicLinkToRemoteVpc,
    pcx.allow_egress_from_local_vpc_to_remote_classic_link =
        vpc_peering.RequesterVpcInfo.PeeringOptions.AllowEgressFromLocalVpcToRemoteClassicLink,
    pcx.requester_region = vpc_peering.RequesterVpcInfo.Region,
    pcx.accepter_region = vpc_peering.AccepterVpcInfo.Region,
    pcx.status_code = vpc_peering.Status.Code,
    pcx.status_message = vpc_peering.Status.Message,
    pcx.arn = vpc_peering.arn,
    pcx.consolelink = vpc_peering.consolelink

    // A side's VPC is linked only when an account of this workspace owns it: this account's own VPC, or a
    // peer account of the same customer. Another customer's VPC is never linked or written; its facts stay
    // in the properties above.
    WITH vpc_peering, pcx
    OPTIONAL MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization)-[:OWNER]->(:AWSAccount)
        -[:RESOURCE]->(avpc:AWSVpc{id: vpc_peering.AccepterVpcInfo.VpcId})
    FOREACH (v IN CASE WHEN avpc IS NULL THEN [] ELSE [avpc] END |
        MERGE (pcx)-[rav:ACCEPTER_VPC]->(v)
        ON CREATE SET rav.firstseen = timestamp()
        SET rav.lastupdated = $update_tag
    )

    WITH DISTINCT vpc_peering, pcx
    OPTIONAL MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization)-[:OWNER]->(:AWSAccount)
        -[:RESOURCE]->(rvpc:AWSVpc{id: vpc_peering.RequesterVpcInfo.VpcId})
    FOREACH (v IN CASE WHEN rvpc IS NULL THEN [] ELSE [rvpc] END |
        MERGE (pcx)-[rrv:REQUESTER_VPC]->(v)
        ON CREATE SET rrv.firstseen = timestamp()
        SET rrv.lastupdated = $update_tag
    )
    """

    for item in data:
        item['arn'] = (
            f"arn:{partition}:ec2:{region}:{aws_account_id}:vpc-peering-connection/{item['VpcPeeringConnectionId']}"
        )
        item['consolelink'] = aws_console_link.get_console_link(arn=item['arn'])

    load_graph_data(
        neo4j_session,
        ingest_vpc_peerings,
        data,
        update_tag=update_tag,
        region=region, aws_account_id=aws_account_id, WORKSPACE_ID=workspace_id,
    )


@timeit
def load_accepter_cidrs(
    neo4j_session: neo4j.Session, data: List[Dict], region: str,
    aws_account_id: str, update_tag: int, workspace_id: str,
) -> None:

    # Blocks of a side whose VPC is in this workspace only (see load_vpc_peerings); the block id embeds
    # the VPC id matched inside the workspace.
    ingest_accepter_cidr = """
    UNWIND $DictList AS vpc_peering
    MATCH (:AWSAccount{id: $aws_account_id})-[:RESOURCE]->
        (pcx:AWSPeeringConnection{id: vpc_peering.VpcPeeringConnectionId})
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization)-[:OWNER]->(:AWSAccount)
        -[:RESOURCE]->(vpc:AWSVpc{id: vpc_peering.AccepterVpcInfo.VpcId})
    WITH DISTINCT vpc_peering, pcx, vpc
    UNWIND vpc_peering.AccepterVpcInfo.CidrBlockSet AS c_b

    MERGE (cb:AWSCidrBlock:AWSIpv4CidrBlock{id: vpc.id + '|' + c_b.CidrBlock})
    ON CREATE SET cb.firstseen = timestamp()
    SET cb.lastupdated = $update_tag, cb.cidr_block  =  c_b.CidrBlock

    MERGE (pcx)-[r:ACCEPTER_CIDR]->(cb)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag

    MERGE (vpc)-[b:BLOCK_ASSOCIATION]->(cb)
    ON CREATE SET b.firstseen = timestamp()
    SET b.lastupdated = $update_tag
    """

    load_graph_data(
        neo4j_session,
        ingest_accepter_cidr,
        data,
        update_tag=update_tag,
        aws_account_id=aws_account_id, WORKSPACE_ID=workspace_id,
    )


@timeit
def load_requester_cidrs(
    neo4j_session: neo4j.Session, data: List[Dict], region: str,
    aws_account_id: str, update_tag: int, workspace_id: str,
) -> None:

    # Same as load_accepter_cidrs, for the requester side.
    ingest_requester_cidr = """
    UNWIND $DictList AS vpc_peering
    MATCH (:AWSAccount{id: $aws_account_id})-[:RESOURCE]->
        (pcx:AWSPeeringConnection{id: vpc_peering.VpcPeeringConnectionId})
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization)-[:OWNER]->(:AWSAccount)
        -[:RESOURCE]->(vpc:AWSVpc{id: vpc_peering.RequesterVpcInfo.VpcId})
    WITH DISTINCT vpc_peering, pcx, vpc
    UNWIND vpc_peering.RequesterVpcInfo.CidrBlockSet AS c_b

    MERGE (cb:AWSCidrBlock:AWSIpv4CidrBlock{id: vpc.id + '|' + c_b.CidrBlock})
    ON CREATE SET cb.firstseen = timestamp()
    SET cb.lastupdated = $update_tag, cb.cidr_block  =  c_b.CidrBlock

    MERGE (pcx)-[r:REQUESTER_CIDR]->(cb)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag

    MERGE (vpc)-[b:BLOCK_ASSOCIATION]->(cb)
    ON CREATE SET b.firstseen = timestamp()
    SET b.lastupdated = $update_tag
    """

    load_graph_data(
        neo4j_session,
        ingest_requester_cidr,
        data,
        update_tag=update_tag,
        aws_account_id=aws_account_id, WORKSPACE_ID=workspace_id,
    )


@timeit
def cleanup_vpc_peerings(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_vpc_peering_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_vpc_peerings(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
    current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing EC2 VPC Peerings for account '%s', at %s.", current_aws_account_id, tic)

    partition = get_partition_from_params(common_job_parameters)
    workspace_id = common_job_parameters['WORKSPACE_ID']
    for region in regions:
        logger.debug("Syncing EC2 VPC peering for region '%s' in account '%s'.", region, current_aws_account_id)
        data = get_vpc_peerings_data(boto3_session, region)

        logger.info(f"Total VPC Peering data: {len(data)} for {region}")

        load_vpc_peerings(
            neo4j_session, data, region, current_aws_account_id, update_tag, workspace_id, partition=partition,
        )
        load_accepter_cidrs(neo4j_session, data, region, current_aws_account_id, update_tag, workspace_id)
        load_requester_cidrs(neo4j_session, data, region, current_aws_account_id, update_tag, workspace_id)
    cleanup_vpc_peerings(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process EC2 VPC Peerings: {toc - tic:0.4f} seconds")
