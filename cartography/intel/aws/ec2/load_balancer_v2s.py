import logging
import time
from typing import Dict
from typing import List

import boto3
import botocore
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from .util import get_botocore_config
from cartography.client.core.tx import load_graph_data
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_load_balancer_v2_listeners(client: botocore.client.BaseClient, load_balancer_arn: str, region: str) -> List[Dict]:
    paginator = client.get_paginator('describe_listeners')
    listeners: List[Dict] = []
    try:
        for page in paginator.paginate(LoadBalancerArn=load_balancer_arn):
            listeners.extend(page['Listeners'])

    except Exception as e:
        logger.warning(f"Failed retrieve load balancer listeners for region -{region} . Error - {e}")

    return listeners


@timeit
def get_load_balancer_v2_target_groups(client: botocore.client.BaseClient, load_balancer_arn: str) -> List[Dict]:
    paginator = client.get_paginator('describe_target_groups')
    target_groups: List[Dict] = []
    for page in paginator.paginate(LoadBalancerArn=load_balancer_arn):
        target_groups.extend(page['TargetGroups'])

    # Add instance data
    for target_group in target_groups:
        target_group['Targets'] = []
        target_health = client.describe_target_health(TargetGroupArn=target_group['TargetGroupArn'])
        for target_health_description in target_health['TargetHealthDescriptions']:
            target_group['Targets'].append(target_health_description['Target']['Id'])

    return target_groups


@timeit
@aws_handle_regions
def get_loadbalancer_v2_data(boto3_session: boto3.Session, region: str) -> List[Dict]:
    client = boto3_session.client('elbv2', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_load_balancers')
    elbv2s: List[Dict] = []
    for page in paginator.paginate():
        elbv2s.extend(page['LoadBalancers'])

    # Make extra calls to get listeners
    for elbv2 in elbv2s:
        elbv2['Listeners'] = get_load_balancer_v2_listeners(client, elbv2['LoadBalancerArn'], region)
        elbv2['TargetGroups'] = get_load_balancer_v2_target_groups(client, elbv2['LoadBalancerArn'])
        elbv2['region'] = region
    return elbv2s


@timeit
def load_load_balancer_v2s(
    neo4j_session: neo4j.Session, data: List[Dict], current_aws_account_id: str,
    update_tag: int, region: str,
) -> None:
    ingest_load_balancer_v2 = """
    UNWIND $DictList AS item
    MERGE (elbv2:LoadBalancerV2{id: item.id})
    ON CREATE SET elbv2.firstseen = timestamp(), elbv2.createdtime = item.createdtime
    SET elbv2.lastupdated = $update_tag, elbv2.name = item.name, elbv2.dnsname = item.id,
    elbv2.canonicalhostedzonenameid = item.hosted_zone_name_id,
    elbv2.type = item.type,
    elbv2.scheme = item.scheme, elbv2.region = item.region,
    elbv2.arn = item.arn,
    elbv2.consolelink = item.consolelink
    WITH elbv2
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(elbv2)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    lb_rows, subnet_rows, sg_rows, listener_rows, instance_rows = [], [], [], [], []
    for lb in data:
        region = lb.get('region', '')
        load_balancer_arn = lb["LoadBalancerArn"]
        load_balancer_id = lb.get("DNSName") or load_balancer_arn

        lb_rows.append({
            "id": load_balancer_id,
            "createdtime": str(lb["CreatedTime"]),
            "name": lb["LoadBalancerName"],
            "hosted_zone_name_id": lb.get("CanonicalHostedZoneNameID"),
            "type": lb.get("Type"),
            "scheme": lb.get("Scheme"),
            "region": region,
            "arn": load_balancer_arn,
            "consolelink": aws_console_link.get_console_link(arn=load_balancer_arn),
        })
        subnet_rows.extend(
            {"load_balancer_id": load_balancer_id, "subnet_id": az['SubnetId'], "region": region}
            for az in lb["AvailabilityZones"] or []
        )
        # NLB's don't have SecurityGroups, so check for one first.
        if 'SecurityGroups' in lb and lb["SecurityGroups"]:
            sg_rows.extend(
                {"load_balancer_id": load_balancer_id, "group_id": str(group)}
                for group in lb["SecurityGroups"]
            )
        if lb.get('Listeners'):
            listener_rows.append({"load_balancer_id": load_balancer_id, "listeners": lb['Listeners']})
        instance_rows.extend(_build_target_group_instance_rows(load_balancer_id, lb.get('TargetGroups') or []))

    load_graph_data(
        neo4j_session, ingest_load_balancer_v2, lb_rows,
        AWS_ACCOUNT_ID=current_aws_account_id, update_tag=update_tag,
    )
    _load_lb_v2_subnet_rows(neo4j_session, subnet_rows, update_tag)
    ingest_load_balancer_v2_security_group = """
    UNWIND $DictList AS item
    MATCH (elbv2:LoadBalancerV2{id: item.load_balancer_id}),
    (group:EC2SecurityGroup{groupid: item.group_id})
    MERGE (elbv2)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """
    load_graph_data(neo4j_session, ingest_load_balancer_v2_security_group, sg_rows, update_tag=update_tag)
    _load_lb_v2_listener_rows(neo4j_session, listener_rows, update_tag)
    _load_lb_v2_instance_rows(neo4j_session, instance_rows, current_aws_account_id, update_tag)


def _build_target_group_instance_rows(load_balancer_id: str, target_groups: List[Dict]) -> List[Dict]:
    return [
        {
            "load_balancer_id": load_balancer_id,
            "instance_id": instance,
            "target_group_arn": target_group.get('TargetGroupArn'),
            "port": target_group.get('Port'),
            "protocol": target_group.get('Protocol'),
        }
        for target_group in target_groups
        # Only working on EC2 Instances now. TODO: Add IP & Lambda EXPOSE.
        if target_group['TargetType'] == 'instance'
        for instance in target_group["Targets"]
    ]


def _load_lb_v2_subnet_rows(neo4j_session: neo4j.Session, subnet_rows: List[Dict], update_tag: int) -> None:
    ingest_load_balancer_subnet = """
    UNWIND $DictList AS item
    MATCH (elbv2:LoadBalancerV2{id: item.load_balancer_id})
    MERGE (subnet:EC2Subnet{subnetid: item.subnet_id})
    ON CREATE SET subnet.firstseen = timestamp()
    SET subnet.region = item.region, subnet.lastupdated = $update_tag
    WITH elbv2, subnet
    MERGE (elbv2)-[r:SUBNET]->(subnet)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """
    load_graph_data(neo4j_session, ingest_load_balancer_subnet, subnet_rows, update_tag=update_tag)


def _load_lb_v2_instance_rows(
    neo4j_session: neo4j.Session, instance_rows: List[Dict], current_aws_account_id: str, update_tag: int,
) -> None:
    ingest_instances = """
    UNWIND $DictList AS item
    MATCH (elbv2:LoadBalancerV2{id: item.load_balancer_id}), (instance:EC2Instance{instanceid: item.instance_id})
    MERGE (elbv2)-[r:EXPOSE]->(instance)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag,
        r.port = item.port, r.protocol = item.protocol,
        r.target_group_arn = item.target_group_arn
    WITH instance
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(instance)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """
    load_graph_data(
        neo4j_session, ingest_instances, instance_rows,
        AWS_ACCOUNT_ID=current_aws_account_id, update_tag=update_tag,
    )


def _load_lb_v2_listener_rows(neo4j_session: neo4j.Session, listener_rows: List[Dict], update_tag: int) -> None:
    ingest_listener = """
    UNWIND $DictList AS item
    MATCH (elbv2:LoadBalancerV2{id: item.load_balancer_id})
    WITH elbv2, item
    UNWIND item.listeners as data
        MERGE (l:Endpoint:ELBV2Listener{id: data.ListenerArn})
        ON CREATE SET l.port = data.Port, l.protocol = data.Protocol,
        l.firstseen = timestamp(),
        l.targetgrouparn = data.TargetGroupArn
        SET l.lastupdated = $update_tag,
        l.ssl_policy = data.SslPolicy,
        l.arn = data.ListenerArn
        WITH l, elbv2
        MERGE (elbv2)-[r:ELBV2_LISTENER]->(l)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $update_tag
    """
    load_graph_data(neo4j_session, ingest_listener, listener_rows, update_tag=update_tag)


@timeit
def load_load_balancer_v2_subnets(
    neo4j_session: neo4j.Session, load_balancer_id: str, az_data: List[Dict],
    region: str, update_tag: int,
) -> None:
    _load_lb_v2_subnet_rows(
        neo4j_session,
        [{"load_balancer_id": load_balancer_id, "subnet_id": az['SubnetId'], "region": region} for az in az_data],
        update_tag,
    )


@timeit
def load_load_balancer_v2_target_groups(
    neo4j_session: neo4j.Session, load_balancer_id: str, target_groups: List[Dict], current_aws_account_id: str,
    update_tag: int,
) -> None:
    _load_lb_v2_instance_rows(
        neo4j_session,
        _build_target_group_instance_rows(load_balancer_id, target_groups),
        current_aws_account_id,
        update_tag,
    )


@timeit
def load_load_balancer_v2_listeners(
    neo4j_session: neo4j.Session, load_balancer_id: str, listener_data: List[Dict],
    update_tag: int,
) -> None:
    _load_lb_v2_listener_rows(
        neo4j_session,
        [{"load_balancer_id": load_balancer_id, "listeners": listener_data}],
        update_tag,
    )


@timeit
def cleanup_load_balancer_v2s(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    """Delete elbv2's and dependent resources in the DB without the most recent lastupdated tag."""
    run_cleanup_job('aws_ingest_load_balancers_v2_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_load_balancer_v2s(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing EC2 load balancers v2 for account '%s', at %s.", current_aws_account_id, tic)

    data = []
    for region in regions:
        logger.info("Syncing EC2 load balancers v2 for region '%s' in account '%s'.", region, current_aws_account_id)
        data.extend(get_loadbalancer_v2_data(boto3_session, region))
        logger.info(f"Total Load Balancer V2s: {len(data)}")
        load_load_balancer_v2s(neo4j_session, data, current_aws_account_id, update_tag, region)

    cleanup_load_balancer_v2s(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process EC2 load balancers v2: {toc - tic:0.4f} seconds")
