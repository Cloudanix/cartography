import logging
import time
from string import Template
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from .util import get_botocore_config
from cartography.client.core.tx import load_graph_data
from cartography.graph.job import GraphJob
from cartography.models.aws.ec2.securitygroup_instance import EC2SecurityGroupInstanceSchema
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit
logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_ec2_security_group_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client('ec2', region_name=region, config=get_botocore_config())
    security_groups = []
    try:
        paginator = client.get_paginator('describe_security_groups')
        security_groups: List[Dict] = []
        for page in paginator.paginate():
            security_groups.extend(page['SecurityGroups'])
        for group in security_groups:
            groupName = group.get('GroupName', '')

            if groupName == 'default':
                group['isDefault'] = True
            else:
                group['isDefault'] = False

            group['region'] = region
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDeniedException' or e.response['Error']['Code'] == 'UnauthorizedOperation':
            logger.warning(
                'ec2:describe_security_groups failed with AccessDeniedException; continuing sync.',
                exc_info=True,
            )
        else:
            raise

    return security_groups


def _build_rule_and_range_rows(groups: List[Dict]) -> tuple:
    """
    Flatten group x rule-type x rule (and their IP ranges) into rows, partitioned by
    node label since each label needs its own query. This was a per-item nested loop.
    """
    rule_rows: Dict[str, List[Dict]] = {"IpPermissionInbound": [], "IpPermissionEgress": []}
    range_rows: Dict[str, List[Dict]] = {"IpRange": [], "Ipv6Range": []}
    rule_type_map = {"IpPermissions": "IpPermissionInbound", "IpPermissionsEgress": "IpPermissionEgress"}

    for group in groups:
        group_id = group["GroupId"]
        for rule_type, rule_label in rule_type_map.items():
            for rule in group.get(rule_type) or []:
                protocol = rule.get("IpProtocol", "all")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                # NOTE This hardcoding is done because some, rules might be applicable for all protocols in that case
                # the value of protocol variable would be -1 (or all) this means it will also be available for all
                # ports, hence from_port & to_port values might not be provided
                # Docs: boto3 EC2 Client.describe_security_groups reference
                if protocol == "-1" or protocol == "all":
                    from_port = 0  # the smallest possible IP
                    to_port = 65535  # the largest possible IP

                ruleid = f"{group_id}/{rule_type}/{from_port}{to_port}{protocol}"
                rule_rows[rule_label].append({
                    "ruleid": ruleid,
                    "from_port": from_port,
                    "to_port": to_port,
                    "protocol": protocol,
                    "group_id": group_id,
                })

                for ip_range in rule["IpRanges"]:
                    cidr_ip = ip_range['CidrIp']
                    range_rows["IpRange"].append({
                        "range_id": f"IpRule/{ruleid}/ipRange/{cidr_ip}",
                        "range": cidr_ip,
                        "range_name": cidr_ip.split('/')[0],
                        "ruleid": ruleid,
                    })

                for ipv6_range in rule["Ipv6Ranges"]:
                    cidr_ipv6 = ipv6_range['CidrIpv6']
                    range_rows["Ipv6Range"].append({
                        "range_id": f"IpRule/{ruleid}/ipv6Range/{cidr_ipv6}",
                        "range": cidr_ipv6,
                        "range_name": cidr_ipv6.split('/')[0],
                        "ruleid": ruleid,
                    })

    return rule_rows, range_rows


@timeit
def load_ec2_security_group_rules(neo4j_session: neo4j.Session, groups: List[Dict], update_tag: int) -> None:
    INGEST_RULE_TEMPLATE = Template("""
    UNWIND $DictList AS item
    MERGE (rule:$rule_label{ruleid: item.ruleid})
    ON CREATE SET rule :IpRule, rule.firstseen = timestamp(), rule.fromport = item.from_port,
    rule.toport = item.to_port,
    rule.protocol = item.protocol
    SET rule.lastupdated = $update_tag
    WITH rule, item
    MATCH (group:EC2SecurityGroup{groupid: item.group_id})
    MERGE (group)<-[r:MEMBER_OF_EC2_SECURITY_GROUP]-(rule)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag;
    """)

    ingest_rule_group_pair = """
    UNWIND $DictList AS item
    MERGE (group:EC2SecurityGroup{id: item.group_id})
    ON CREATE SET group.firstseen = timestamp(), group.groupid = item.group_id
    SET group.lastupdated = $update_tag
    WITH group, item
    MATCH (inbound:IpRule{ruleid: item.ruleid})
    MERGE (inbound)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    ingest_range = Template("""
    UNWIND $DictList AS item
    MERGE (range:$range_label{id: item.range_id})
    ON CREATE SET range.firstseen = timestamp(), range.range = item.range
    SET range.lastupdated = $update_tag, range.name = item.range_name
    WITH range, item
    MATCH (rule:IpRule{ruleid: item.ruleid})
    MERGE (rule)<-[r:MEMBER_OF_IP_RULE]-(range)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """)

    rule_rows, range_rows = _build_rule_and_range_rows(groups)

    for rule_label, rows in rule_rows.items():
        load_graph_data(
            neo4j_session,
            INGEST_RULE_TEMPLATE.safe_substitute(rule_label=rule_label),
            rows,
            update_tag=update_tag,
        )
    load_graph_data(
        neo4j_session,
        ingest_rule_group_pair,
        rule_rows["IpPermissionInbound"] + rule_rows["IpPermissionEgress"],
        update_tag=update_tag,
    )
    for range_label, rows in range_rows.items():
        load_graph_data(
            neo4j_session,
            ingest_range.safe_substitute(range_label=range_label),
            rows,
            update_tag=update_tag,
        )


@timeit
def load_ec2_security_groupinfo(
    neo4j_session: neo4j.Session, data: List[Dict],
    current_aws_account_id: str, update_tag: int,
) -> None:
    ingest_security_group = """
    UNWIND $DictList AS item
    MERGE (group:EC2SecurityGroup{id: item.group_id})
    ON CREATE SET group.firstseen = timestamp(), group.groupid = item.group_id
    SET group.name = item.group_name, group.description = item.description,
    group.consolelink = item.consolelink,
    group.region = item.region,
    group.lastupdated = $update_tag, group.arn = item.group_arn,
    group.is_default = item.is_default
    WITH group, item
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH group, item
    MATCH (vpc:AWSVpc{id: item.vpc_id})
    MERGE (vpc)-[rg:MEMBER_OF_EC2_SECURITY_GROUP]->(group)
    ON CREATE SET rg.firstseen = timestamp()
    """

    group_rows = []
    for group in data:
        region = group.get('region', '')
        group_id = group["GroupId"]
        group_arn = f"arn:aws:ec2:{region}:{current_aws_account_id}:security-group/{group_id}"

        consolelink = ''
        try:
            consolelink = aws_console_link.get_console_link(arn=group_arn)
        except Exception as ex:
            logger.error("failed to generate console link for security group %s: %s", group_arn, ex)

        group_rows.append({
            "group_id": group_id,
            "group_arn": group_arn,
            "consolelink": consolelink,
            "group_name": group.get("GroupName"),
            "description": group.get("Description"),
            "vpc_id": group.get("VpcId", None),
            "region": region,
            "is_default": group.get("isDefault", None),
        })

    load_graph_data(
        neo4j_session,
        ingest_security_group,
        group_rows,
        AWS_ACCOUNT_ID=current_aws_account_id,
        update_tag=update_tag,
    )
    load_ec2_security_group_rules(neo4j_session, data, update_tag)


@timeit
def cleanup_ec2_security_groupinfo(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job(
        'aws_import_ec2_security_groupinfo_cleanup.json',
        neo4j_session,
        common_job_parameters,
    )
    GraphJob.from_node_schema(EC2SecurityGroupInstanceSchema(), common_job_parameters).run(neo4j_session)


@timeit
def sync_ec2_security_groupinfo(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing EC2 security groups for account '%s', at %s.", current_aws_account_id, tic)

    data = []
    for region in regions:
        logger.info("Syncing EC2 security groups for region '%s' in account '%s'.", region, current_aws_account_id)
        data.extend(get_ec2_security_group_data(boto3_session, region))

    logger.info(f"Total EC2 Security Groups: {len(data)}")

    load_ec2_security_groupinfo(neo4j_session, data, current_aws_account_id, update_tag)
    cleanup_ec2_security_groupinfo(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process EC2 security groups: {toc - tic:0.4f} seconds")
