import logging
import time
from typing import Dict
from typing import List

import boto3
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
def get_loadbalancer_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('elb', region_name=region, config=get_botocore_config())
    paginator = client.get_paginator('describe_load_balancers')
    elbs: List[Dict] = []
    try:
        for page in paginator.paginate():
            elbs.extend(page['LoadBalancerDescriptions'])
        for elb in elbs:
            elb['region'] = region

    except Exception as e:
        logger.warning(f"Failed retrieve load balancers for region - {region}. Error - {e}")

    return elbs


@timeit
def load_load_balancer_listeners(
    neo4j_session: neo4j.Session, listener_rows: List[Dict], update_tag: int,
) -> None:
    """Each row: load_balancer_id, consolelink, listeners (the ListenerDescriptions list)."""
    ingest_listener = """
    UNWIND $DictList AS item
    MATCH (elb:LoadBalancer{id: item.load_balancer_id})
    WITH elb, item
    UNWIND item.listeners as data
        MERGE (l:Endpoint:ELBListener{id: elb.id + toString(data.Listener.LoadBalancerPort) +
                toString(data.Listener.Protocol)})
        ON CREATE SET l.port = data.Listener.LoadBalancerPort, l.protocol = data.Listener.Protocol,
        l.consolelink = item.consolelink,
        l.firstseen = timestamp()
        SET l.instance_port = data.Listener.InstancePort, l.instance_protocol = data.Listener.InstanceProtocol,
        l.policy_names = data.PolicyNames,
        l.lastupdated = $update_tag
        WITH l, elb
        MERGE (elb)-[r:ELB_LISTENER]->(l)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $update_tag
    """
    load_graph_data(neo4j_session, ingest_listener, listener_rows, update_tag=update_tag)


@timeit
def load_load_balancer_subnets(
    neo4j_session: neo4j.Session, subnet_rows: List[Dict], update_tag: int,
) -> None:
    """Each row: load_balancer_id, subnet_id."""
    ingest_load_balancer_subnet = """
    UNWIND $DictList AS item
    MATCH (elb:LoadBalancer{id: item.load_balancer_id}), (subnet:EC2Subnet{subnetid: item.subnet_id})
    MERGE (elb)-[r:SUBNET]->(subnet)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """
    load_graph_data(neo4j_session, ingest_load_balancer_subnet, subnet_rows, update_tag=update_tag)


@timeit
def load_load_balancers(
    neo4j_session: neo4j.Session, data: List[Dict], current_aws_account_id: str,
    update_tag: int,
) -> None:
    ingest_load_balancer = """
    UNWIND $DictList AS item
    MERGE (elb:LoadBalancer{id: item.id})
    ON CREATE SET elb.firstseen = timestamp(), elb.createdtime = item.createdtime
    SET elb.lastupdated = $update_tag, elb.name = item.name, elb.dnsname = item.id,
    elb.canonicalhostedzonename = item.hosted_zone_name, elb.canonicalhostedzonenameid = item.hosted_zone_name_id,
    elb.scheme = item.scheme, elb.region = item.region, elb.arn = item.arn
    WITH elb
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(elb)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    ingest_load_balancersource_security_group = """
    UNWIND $DictList AS item
    MATCH (elb:LoadBalancer{id: item.load_balancer_id}),
    (group:EC2SecurityGroup{name: item.group_name})
    MERGE (elb)-[r:SOURCE_SECURITY_GROUP]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    ingest_load_balancer_security_group = """
    UNWIND $DictList AS item
    MATCH (elb:LoadBalancer{id: item.load_balancer_id}),
    (group:EC2SecurityGroup{groupid: item.group_id})
    MERGE (elb)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    ingest_instances = """
    UNWIND $DictList AS item
    MATCH (elb:LoadBalancer{id: item.load_balancer_id}), (instance:EC2Instance{instanceid: item.instance_id})
    MERGE (elb)-[r:EXPOSE]->(instance)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH instance
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(instance)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    lb_rows, subnet_rows, sg_rows, source_sg_rows, instance_rows, listener_rows = [], [], [], [], [], []
    for lb in data:
        region = lb.get('region', '')
        load_balancer_id = lb["DNSName"]
        load_balancer_arn = \
            f"arn:aws:elasticloadbalancing:{region}:{current_aws_account_id}:loadbalancer/{load_balancer_id}"
        console_arn = \
            f"arn:aws:elasticloadbalancing:{region}:{current_aws_account_id}:loadbalancer/{lb['LoadBalancerName']}"
        consolelink = aws_console_link.get_console_link(arn=console_arn)

        lb_rows.append({
            "id": load_balancer_id,
            "createdtime": str(lb["CreatedTime"]),
            "name": lb["LoadBalancerName"],
            "hosted_zone_name": lb.get("CanonicalHostedZoneName"),
            "hosted_zone_name_id": lb.get("CanonicalHostedZoneNameID"),
            "scheme": lb.get("Scheme", ""),
            "region": region,
            "arn": load_balancer_arn,
        })
        subnet_rows.extend(
            {"load_balancer_id": load_balancer_id, "subnet_id": subnet_id}
            for subnet_id in lb["Subnets"] or []
        )
        sg_rows.extend(
            {"load_balancer_id": load_balancer_id, "group_id": str(group)}
            for group in lb["SecurityGroups"] or []
        )
        if lb["SourceSecurityGroup"]:
            source_sg_rows.append({
                "load_balancer_id": load_balancer_id,
                "group_name": lb["SourceSecurityGroup"]["GroupName"],
            })
        instance_rows.extend(
            {"load_balancer_id": load_balancer_id, "instance_id": instance["InstanceId"]}
            for instance in lb["Instances"] or []
        )
        if lb["ListenerDescriptions"]:
            listener_rows.append({
                "load_balancer_id": load_balancer_id,
                "consolelink": consolelink,
                "listeners": lb["ListenerDescriptions"],
            })

    load_graph_data(
        neo4j_session, ingest_load_balancer, lb_rows,
        AWS_ACCOUNT_ID=current_aws_account_id, update_tag=update_tag,
    )
    load_load_balancer_subnets(neo4j_session, subnet_rows, update_tag)
    load_graph_data(neo4j_session, ingest_load_balancer_security_group, sg_rows, update_tag=update_tag)
    load_graph_data(neo4j_session, ingest_load_balancersource_security_group, source_sg_rows, update_tag=update_tag)
    load_graph_data(
        neo4j_session, ingest_instances, instance_rows,
        AWS_ACCOUNT_ID=current_aws_account_id, update_tag=update_tag,
    )
    load_load_balancer_listeners(neo4j_session, listener_rows, update_tag)


@timeit
def cleanup_load_balancers(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_ingest_load_balancers_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_load_balancers(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing EC2 load balancers for account '%s', at %s.", current_aws_account_id, tic)

    data = []
    for region in regions:
        logger.info("Syncing EC2 load balancers for region '%s' in account '%s'.", region, current_aws_account_id)
        data.extend(get_loadbalancer_data(boto3_session, region))

    logger.info(f"Total Load Balancers: {len(data)}")

    load_load_balancers(neo4j_session, data, current_aws_account_id, update_tag)
    cleanup_load_balancers(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process EC2 load balancers: {toc - tic:0.4f} seconds")
