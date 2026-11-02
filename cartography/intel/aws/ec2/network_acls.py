"""
EC2 network ACLs: stateless, ordered subnet filters. Needed by the L2 reachability walker
(docs/exposure-layers/plan.md): a public IP plus an open security group is not reachable
when the subnet's NACL denies the port or the ephemeral reply ports.

Graph:
    (:AWSAccount)-[:RESOURCE]->(:EC2NetworkAcl)-[:MEMBER_OF_AWS_VPC]->(:AWSVpc)
    (:EC2NetworkAcl)-[:PART_OF_SUBNET]->(:EC2Subnet)
    (:EC2NetworkAclRule)-[:MEMBER_OF_NACL]->(:EC2NetworkAcl)
"""
import logging
import time
from typing import Dict
from typing import List
from typing import Tuple

import boto3
import neo4j
from botocore.exceptions import ClientError

from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.intel.aws.util.arns import DEFAULT_PARTITION
from cartography.intel.aws.util.arns import get_partition_from_params
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

_ACCESS_DENIED = {"AccessDeniedException", "UnauthorizedOperation"}


@timeit
@aws_handle_regions
def get_network_acls(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client("ec2", region_name=region, config=get_botocore_config())
    acls: List[Dict] = []
    try:
        for page in client.get_paginator("describe_network_acls").paginate():
            acls.extend(page["NetworkAcls"])
    except ClientError as e:
        if e.response["Error"]["Code"] not in _ACCESS_DENIED:
            raise
        logger.warning("ec2:DescribeNetworkAcls denied in %s; continuing sync.", region)
    return acls


def transform_network_acls(
    acls: List[Dict], region: str, account_id: str, partition: str = DEFAULT_PARTITION,
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    :return: (acl rows, rule rows, subnet association rows)
    """
    acl_rows: List[Dict] = []
    rule_rows: List[Dict] = []
    assoc_rows: List[Dict] = []
    for acl in acls:
        acl_id = acl["NetworkAclId"]
        acl_rows.append({
            "id": acl_id,
            "arn": f"arn:{partition}:ec2:{region}:{acl.get('OwnerId', account_id)}:network-acl/{acl_id}",
            "is_default": acl.get("IsDefault", False),
            "vpc_id": acl.get("VpcId"),
            "region": region,
        })
        for entry in acl.get("Entries", []):
            rule_rows.append(_transform_entry(acl_id, entry))
        for assoc in acl.get("Associations", []):
            if assoc.get("SubnetId"):
                assoc_rows.append({"acl_id": acl_id, "subnet_id": assoc["SubnetId"]})
    return acl_rows, rule_rows, assoc_rows


def _transform_entry(acl_id: str, entry: Dict) -> Dict:
    direction = "egress" if entry.get("Egress") else "inbound"
    port_range = entry.get("PortRange") or {}
    return {
        "id": f"{acl_id}/{direction}/{entry['RuleNumber']}",
        "acl_id": acl_id,
        "rule_number": entry["RuleNumber"],
        "protocol": entry.get("Protocol"),
        "rule_action": entry.get("RuleAction"),
        "egress": bool(entry.get("Egress")),
        "cidr_block": entry.get("CidrBlock"),
        "ipv6_cidr_block": entry.get("Ipv6CidrBlock"),
        "from_port": port_range.get("From"),
        "to_port": port_range.get("To"),
    }


@timeit
def load_network_acls(
    neo4j_session: neo4j.Session, acl_rows: List[Dict], rule_rows: List[Dict], assoc_rows: List[Dict],
    account_id: str, update_tag: int,
) -> None:
    load_graph_data(neo4j_session, _ACL_QUERY, acl_rows, aws_account_id=account_id, update_tag=update_tag)
    load_graph_data(neo4j_session, _RULE_QUERY, rule_rows, update_tag=update_tag)
    load_graph_data(neo4j_session, _ASSOC_QUERY, assoc_rows, update_tag=update_tag)


_ACL_QUERY = """
UNWIND $DictList AS row
MERGE (acl:EC2NetworkAcl{id: row.id})
ON CREATE SET acl.firstseen = timestamp()
SET acl.arn = row.arn, acl.network_acl_id = row.id, acl.is_default = row.is_default,
    acl.vpc_id = row.vpc_id, acl.region = row.region, acl.lastupdated = $update_tag
WITH acl, row
MATCH (owner:AWSAccount{id: $aws_account_id})
MERGE (owner)-[r:RESOURCE]->(acl)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $update_tag
WITH acl, row
MATCH (vpc:AWSVpc{id: row.vpc_id})
MERGE (acl)-[v:MEMBER_OF_AWS_VPC]->(vpc)
ON CREATE SET v.firstseen = timestamp()
SET v.lastupdated = $update_tag
"""

_RULE_QUERY = """
UNWIND $DictList AS row
MATCH (acl:EC2NetworkAcl{id: row.acl_id})
MERGE (rule:EC2NetworkAclRule{id: row.id})
ON CREATE SET rule.firstseen = timestamp()
SET rule.rule_number = row.rule_number, rule.protocol = row.protocol, rule.rule_action = row.rule_action,
    rule.egress = row.egress, rule.cidr_block = row.cidr_block, rule.ipv6_cidr_block = row.ipv6_cidr_block,
    rule.fromport = row.from_port, rule.toport = row.to_port, rule.lastupdated = $update_tag
MERGE (rule)-[r:MEMBER_OF_NACL]->(acl)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $update_tag
"""

# Subnet MERGEd by subnetid like route_tables.py: syncs run in parallel, the subnet may not exist yet.
_ASSOC_QUERY = """
UNWIND $DictList AS row
MATCH (acl:EC2NetworkAcl{id: row.acl_id})
MERGE (subnet:EC2Subnet{subnetid: row.subnet_id})
MERGE (acl)-[r:PART_OF_SUBNET]->(subnet)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $update_tag
"""


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("aws_import_network_acls_cleanup.json", neo4j_session, common_job_parameters)


@timeit
def sync_network_acls(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str],
    current_aws_account_id: str, update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    partition = get_partition_from_params(common_job_parameters)
    for region in regions:
        acls = get_network_acls(boto3_session, region)
        acl_rows, rule_rows, assoc_rows = transform_network_acls(acls, region, current_aws_account_id, partition)
        load_network_acls(neo4j_session, acl_rows, rule_rows, assoc_rows, current_aws_account_id, update_tag)
    cleanup(neo4j_session, common_job_parameters)
    logger.info("Time to process EC2 network ACLs: %.4f seconds", time.perf_counter() - tic)
