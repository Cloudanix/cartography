import logging
import re
import time
from collections import namedtuple
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from .util import get_botocore_config
from cartography.client.core.tx import load
from cartography.client.core.tx import load_graph_data
from cartography.graph.job import GraphJob
from cartography.intel.aws.util.arns import DEFAULT_PARTITION
from cartography.intel.aws.util.arns import get_partition_from_params
from cartography.models.aws.ec2.networkinterfaces import EC2NetworkInterfaceSchema
from cartography.models.aws.ec2.privateip_networkinterface import EC2PrivateIpNetworkInterfaceSchema
from cartography.models.aws.ec2.securitygroup_networkinterface import EC2SecurityGroupNetworkInterfaceSchema
from cartography.models.aws.ec2.subnet_networkinterface import EC2SubnetNetworkInterfaceSchema
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


Ec2NetworkData = namedtuple(
    "Ec2NetworkData", [
        "network_interface_list",
        "private_ip_list",
        "sg_list",
        "subnet_list",
    ],
)


@timeit
@aws_handle_regions
def get_network_interface_data(boto3_session: boto3.session.Session, region: str) -> List[Dict[str, Any]]:
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_network_interfaces')
    subnets: List[Dict] = []
    try:
        for page in paginator.paginate():
            subnets.extend(page['NetworkInterfaces'])

    except Exception as e:
        logger.warning(f"Failed retrieve network interfaces for region - {region}. Error - {e}")

    return subnets


def _parse_elb_description(
    description: str, region: str, aws_account_id: str, partition: str,
) -> Tuple[Optional[str], Optional[str]]:
    """
    Returns (classic load balancer name, ALB/NLB/GWLB ARN) named by an ELB-owned ENI's description.
    https://repost.aws/knowledge-center/elb-find-load-balancer-IP
    "ELB app|net|gwy/<name>/<id>" is the tail of the load balancer ARN; "ELB <name>" is a classic one.
    The load balancer lives in the ENI's account and region, so the ARN is built from them.
    """
    v2_match = re.match(r'^ELB ((?:app|net|gwy)/[^/]+/[^/]+)$', description)
    if v2_match:
        return None, f'arn:{partition}:elasticloadbalancing:{region}:{aws_account_id}:loadbalancer/{v2_match[1]}'
    v1_match = re.match(r'^ELB ([A-Za-z0-9-]+)$', description)
    return (v1_match[1] if v1_match else None), None


def transform_network_interface_data(
    data_list: List[Dict[str, Any]], region: str, aws_account_id: str, partition: str = DEFAULT_PARTITION,
) -> Ec2NetworkData:
    network_interface_list = []
    private_ip_list = []
    sg_list = []
    subnet_list = []

    for network_interface in data_list:
        elb_v1_name, elb_v2_arn = _parse_elb_description(
            network_interface.get('Description') or '', region, aws_account_id, partition,
        )
        network_interface_arn = (
            f"arn:{partition}:ec2:{region}:{aws_account_id}:network-interface/{network_interface['NetworkInterfaceId']}"
        )

        # TODO issue #1024 change this to arn when ready
        network_interface_id = network_interface['NetworkInterfaceId']
        network_interface_list.append(
            {
                'Id': network_interface_id,
                'NetworkInterfaceId': network_interface['NetworkInterfaceId'],
                'Description': network_interface['Description'],
                'InstanceId': network_interface.get('Attachment', {}).get('InstanceId'),
                'InterfaceType': network_interface['InterfaceType'],
                'MacAddress': network_interface['MacAddress'],
                'PrivateDnsName': network_interface.get('PrivateDnsName'),
                'PrivateIpAddress': network_interface.get('PrivateIpAddress'),
                'PublicIp': network_interface.get('Association', {}).get('PublicIp'),
                # Read by the ::/0 statement of aws_ec2_instance_asset_exposure.json and the IPv6 half of
                # the exposure-layers reachability walker.
                'Ipv6Addresses': [
                    a['Ipv6Address'] for a in network_interface.get('Ipv6Addresses', []) if a.get('Ipv6Address')
                ],
                'RequesterId': network_interface.get('RequesterId'),
                'RequesterManaged': network_interface.get('RequesterManaged'),
                'SourceDestCheck': network_interface.get('SourceDestCheck'),
                'Status': network_interface.get('Status'),
                'SubnetId': network_interface.get('SubnetId'),
                'ElbV1Name': elb_v1_name,
                'ElbV2Arn': elb_v2_arn,
                'Arn': network_interface_arn,
                'consolelink': aws_console_link.get_console_link(arn=network_interface_arn),
            },
        )
        if network_interface.get('PrivateIpAddresses'):
            for private_ip_address in network_interface['PrivateIpAddresses']:
                private_ip_list.append(
                    {
                        'Id': f"{network_interface['NetworkInterfaceId']}:{private_ip_address['PrivateIpAddress']}",
                        'NetworkInterfaceId': network_interface['NetworkInterfaceId'],
                        'IpOwnerId': private_ip_address.get('Association', {}).get('IpOwnerId'),
                        'Primary': private_ip_address['Primary'],
                        'PrivateIpAddress': private_ip_address['PrivateIpAddress'],
                        'PublicIp': private_ip_address.get('Association', {}).get('PublicIp'),
                    },
                )

        if network_interface.get("Groups"):
            for group in network_interface["Groups"]:
                sg_list.append(
                    {
                        'GroupId': group['GroupId'],
                        'NetworkInterfaceId': network_interface_id,
                    },
                )

        subnet_id = network_interface.get('SubnetId')
        if subnet_id:
            subnet_list.append(
                {
                    'NetworkInterfaceId': network_interface_id,
                    'SubnetId': subnet_id,
                    'ElbV2Arn': elb_v2_arn,
                },
            )

    return Ec2NetworkData(
        network_interface_list=network_interface_list,
        private_ip_list=private_ip_list,
        sg_list=sg_list,
        subnet_list=subnet_list,
    )


@timeit
def load_network_interfaces(
        neo4j_session: neo4j.Session,
        data: List[Dict[str, Any]],
        region: str,
        aws_account_id: str,
        update_tag: int,
) -> None:
    logger.info(f"Loading {len(data)} network interfaces in {region}.")
    load(
        neo4j_session,
        EC2NetworkInterfaceSchema(),
        data,
        Region=region,
        AWS_ID=aws_account_id,
        lastupdated=update_tag,
    )


@timeit
def load_private_ip_network_interface(
        neo4j_session: neo4j.Session,
        data: List[Dict[str, Any]],
        region: str,
        aws_account_id: str,
        update_tag: int,
) -> None:
    """
    Private IPs as known by describe-network-interfaces.
    """
    logger.info(f"Loading {len(data)} private IPs in {region}.")
    load(
        neo4j_session,
        EC2PrivateIpNetworkInterfaceSchema(),
        data,
        Region=region,
        AWS_ID=aws_account_id,
        lastupdated=update_tag,
    )


@timeit
def load_security_group_network_interface(
        neo4j_session: neo4j.Session,
        data: List[Dict[str, Any]],
        region: str,
        aws_account_id: str,
        update_tag: int,
) -> None:
    """
    Security groups as known by describe-network-interfaces.
    """
    logger.info(f"Loading {len(data)} security groups in {region}.")
    load(
        neo4j_session,
        EC2SecurityGroupNetworkInterfaceSchema(),
        data,
        Region=region,
        AWS_ID=aws_account_id,
        lastupdated=update_tag,
    )


@timeit
def load_subnet_network_interface(
        neo4j_session: neo4j.Session,
        data: List[Dict[str, Any]],
        region: str,
        aws_account_id: str,
        update_tag: int,
) -> None:
    """
    Subnets as known by describe-network-interfaces.
    """
    logger.info(f"Loading {len(data)} subnets in {region}.")
    load(
        neo4j_session,
        EC2SubnetNetworkInterfaceSchema(),
        data,
        Region=region,
        AWS_ID=aws_account_id,
        lastupdated=update_tag,
    )


@timeit
def load_classic_elb_network_interfaces(
        neo4j_session: neo4j.Session,
        data: List[Dict[str, Any]],
        region: str,
        aws_account_id: str,
        update_tag: int,
) -> None:
    """
    Links a classic load balancer to its ENIs and their subnets. The ENI names it only by load balancer
    name, which is unique within one account and region, so resolve it among this account's load
    balancers in this region (the LoadBalancer arn holds the DNS name, so there is no global key to match).
    Runs after the subnet load: the subnet link follows the ENI's own PART_OF_SUBNET edge.
    """
    query = """
    UNWIND $DictList AS item
    MATCH (aa:AWSAccount{id: $AWS_ID})-[:RESOURCE]->(ni:NetworkInterface{id: item.NetworkInterfaceId})
    MATCH (aa)-[:RESOURCE]->(elb:LoadBalancer{name: item.ElbV1Name, region: $Region})
    MERGE (elb)-[r:NETWORK_INTERFACE]->(ni)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH elb, ni
    MATCH (ni)-[:PART_OF_SUBNET]->(subnet:EC2Subnet)
    MERGE (elb)-[s:PART_OF_SUBNET]->(subnet)
    ON CREATE SET s.firstseen = timestamp()
    SET s.lastupdated = $update_tag
    """
    rows = [ni for ni in data if ni.get('ElbV1Name')]
    load_graph_data(neo4j_session, query, rows, AWS_ID=aws_account_id, Region=region, update_tag=update_tag)


def load_network_data(
        neo4j_session: neo4j.Session,
        region: str,
        current_aws_account_id: str,
        update_tag: int,
        network_interface_list: List[Dict[str, Any]],
        private_ip_list: List[Dict[str, Any]],
        subnet_list: List[Dict[str, Any]],
        sg_list: List[Dict[str, Any]],
) -> None:
    load_network_interfaces(neo4j_session, network_interface_list, region, current_aws_account_id, update_tag)
    load_private_ip_network_interface(neo4j_session, private_ip_list, region, current_aws_account_id, update_tag)
    load_subnet_network_interface(neo4j_session, subnet_list, region, current_aws_account_id, update_tag)
    load_security_group_network_interface(neo4j_session, sg_list, region, current_aws_account_id, update_tag)
    load_classic_elb_network_interfaces(
        neo4j_session, network_interface_list, region, current_aws_account_id, update_tag,
    )


@timeit
def cleanup_network_interfaces(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    GraphJob.from_node_schema(EC2NetworkInterfaceSchema(), common_job_parameters).run(neo4j_session)
    GraphJob.from_node_schema(EC2PrivateIpNetworkInterfaceSchema(), common_job_parameters).run(neo4j_session)
    # Load balancer links the schema jobs above do not cover (classic ELB, and both kinds' subnet links).
    run_cleanup_job('aws_ec2_network_interface_elb_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def transform_network_interfaces(
    network_interfaces: List[Dict], region: str, aws_account_id: str, partition: str = DEFAULT_PARTITION,
) -> List[Dict]:
    # arn:${Partition}:ec2:${Region}:${Account}:network-interface/${NetworkInterfaceId}
    for ni in network_interfaces:
        ni['Arn'] = f"arn:{partition}:ec2:{region}:{aws_account_id}:network-interface/{ni['NetworkInterfaceId']}"

    return network_interfaces


@timeit
def sync_network_interfaces(
        neo4j_session: neo4j.Session,
        boto3_session: boto3.session.Session,
        regions: List[str],
        current_aws_account_id: str,
        update_tag: int,
        common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing EC2 Network Interfaces for account '%s', at %s.", current_aws_account_id, tic)

    partition = get_partition_from_params(common_job_parameters)
    for region in regions:
        logger.info(f"Syncing EC2 network interfaces for region '{region}' in account '{current_aws_account_id}'.")
        data = get_network_interface_data(boto3_session, region)
        logger.info(f"Total Network Interfaces: {len(data)} for {region}")
        ec2_network_data = transform_network_interface_data(data, region, current_aws_account_id, partition=partition)
        load_network_data(
            neo4j_session,
            region,
            current_aws_account_id,
            update_tag,
            ec2_network_data.network_interface_list,
            ec2_network_data.private_ip_list,
            ec2_network_data.subnet_list,
            ec2_network_data.sg_list,
        )
    cleanup_network_interfaces(neo4j_session, common_job_parameters)
    toc = time.perf_counter()
    logger.info(f"Time to process EC2 Network Interfaces: {toc - tic:0.4f} seconds")
