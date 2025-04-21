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


@timeit
def load_ec2_security_group_rule(neo4j_session: neo4j.Session, group: Dict, rule_type: str, update_tag: int) -> None:
    INGEST_RULE_TEMPLATE = Template("""
    MERGE (rule:$rule_label{ruleid: $RuleId})
    ON CREATE SET rule :IpRule, rule.firstseen = timestamp(), rule.fromport = $FromPort, rule.toport = $ToPort,
    rule.protocol = $Protocol
    SET rule.lastupdated = $update_tag
    WITH rule
    MATCH (group:EC2SecurityGroup{groupid: $GroupId})
    MERGE (group)<-[r:MEMBER_OF_EC2_SECURITY_GROUP]-(rule)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag;
    """)

    ingest_rule_group_pair = """
    MERGE (group:EC2SecurityGroup{id: $GroupId})
    ON CREATE SET group.firstseen = timestamp(), group.groupid = $GroupId
    SET group.lastupdated = $update_tag
    WITH group
    MATCH (inbound:IpRule{ruleid: $RuleId})
    MERGE (inbound)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    ingest_range = Template("""
    MERGE (range:$range_label{id: $RangeId})
    ON CREATE SET range.firstseen = timestamp(), range.range = $Range
    SET range.lastupdated = $update_tag, range.name = split($Range, '/')[0]
    WITH range
    MATCH (rule:IpRule{ruleid: $RuleId})
    MERGE (rule)<-[r:MEMBER_OF_IP_RULE]-(range)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """)

    group_id = group["GroupId"]
    rule_type_map = {"IpPermissions": "IpPermissionInbound", "IpPermissionsEgress": "IpPermissionEgress"}

    if group.get(rule_type):
        for rule in group[rule_type]:
            protocol = rule.get("IpProtocol", "all")
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            # NOTE This hardcoding is done because some, rules might be applicable for all protocols in that case the value of
            # protocol variable would be -1 (or all) this means it will also be available for all ports, hence from_port & to_port values
            # might not be provided
            # Docs Link:https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2/client/describe_security_groups.html
            if protocol == "-1" or protocol == "all":
                from_port = 0  # the smallest possible IP
                to_port = 65535  # the largest possible IP

            ruleid = f"{group_id}/{rule_type}/{from_port}{to_port}{protocol}"
            # NOTE Cypher query syntax is incompatible with Python string formatting, so we have to do this awkward
            # NOTE manual formatting instead.
            neo4j_session.run(
                INGEST_RULE_TEMPLATE.safe_substitute(rule_label=rule_type_map[rule_type]),
                RuleId=ruleid,
                FromPort=from_port,
                ToPort=to_port,
                Protocol=protocol,
                GroupId=group_id,
                update_tag=update_tag,
            )

            neo4j_session.run(
                ingest_rule_group_pair,
                GroupId=group_id,
                RuleId=ruleid,
                update_tag=update_tag,
            )

            for ip_range in rule["IpRanges"]:
                range_id = f"IpRule/{ruleid}/ipRange/{ip_range['CidrIp']}"
                neo4j_session.run(
                    ingest_range.safe_substitute(range_label='IpRange'),
                    RangeId=range_id,
                    Range=ip_range['CidrIp'],
                    RuleId=ruleid,
                    update_tag=update_tag,
                )

            for ipv6_range in rule["Ipv6Ranges"]:
                range_id = f"IpRule/{ruleid}/ipv6Range/{ipv6_range['CidrIpv6']}"
                neo4j_session.run(
                    ingest_range.safe_substitute(range_label='Ipv6Range'),
                    RangeId=range_id,
                    Range=ipv6_range['CidrIpv6'],
                    RuleId=ruleid,
                    update_tag=update_tag,
                )


@timeit
def load_ec2_security_groupinfo(
    neo4j_session: neo4j.Session, data: List[Dict],
    current_aws_account_id: str, update_tag: int,
) -> None:
    ingest_security_group = """
    MERGE (group:EC2SecurityGroup{id: $GroupId})
    ON CREATE SET group.firstseen = timestamp(), group.groupid = $GroupId
    SET group.name = $GroupName, group.description = $Description,
    group.consolelink = $consolelink,
    group.region = $Region,
    group.lastupdated = $update_tag, group.arn = $GroupArn,
    group.is_default = $isDefault
    WITH group
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(group)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH group
    MATCH (vpc:AWSVpc{id: $VpcId})
    MERGE (vpc)-[rg:MEMBER_OF_EC2_SECURITY_GROUP]->(group)
    ON CREATE SET rg.firstseen = timestamp()
    """

    for group in data:
        region = group.get('region', '')
        group_id = group["GroupId"]
        group_arn = f"arn:aws:ec2:{region}:{current_aws_account_id}:security-group/{group_id}"

        consolelink = ''
        try:
            consolelink = aws_console_link.get_console_link(arn=group_arn)
        except Exception as ex:
            logger.error('failed to generate console link for security group', {"key": group_arn}, ex)

        neo4j_session.run(
            ingest_security_group,
            GroupId=group_id,
            GroupArn=group_arn,
            consolelink=consolelink,
            GroupName=group.get("GroupName"),
            Description=group.get("Description"),
            VpcId=group.get("VpcId", None),
            Region=region,
            AWS_ACCOUNT_ID=current_aws_account_id,
            update_tag=update_tag,
            isDefault=group.get("isDefault", None),
        )

        load_ec2_security_group_rule(neo4j_session, group, "IpPermissions", update_tag)
        load_ec2_security_group_rule(neo4j_session, group, "IpPermissionsEgress", update_tag)


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
