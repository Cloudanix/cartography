import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from botocore.exceptions import ClientError
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


def filter_active_redshift_reserved_nodes(reserved_nodes: List[Dict]) -> List[Dict]:
    """Keep only reserved Redshift nodes in active state."""
    return [node for node in reserved_nodes if node.get("State") == "active"]


@timeit
@aws_handle_regions
def get_redshift_reserved_node(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    try:
        client = boto3_session.client("redshift", region_name=region, config=get_botocore_config())
        paginator = client.get_paginator("describe_reserved_nodes")
        reserved_nodes: List = []
        for page in paginator.paginate():
            reserved_nodes.extend(page["ReservedNodes"])
        return filter_active_redshift_reserved_nodes(reserved_nodes)

    except ClientError as e:
        logger.error(f"Failed to call redshift describe_reserved_nodes: {region} - {e}")
        return reserved_nodes


@timeit
def transform_reserved_nodes(nds: List[Dict], region: str, current_aws_account_id: str) -> List[Dict]:
    reserved_nodes = []
    for reserved_node in nds:
        reserved_node["region"] = region
        reserved_node["arn"] = (
            f"arn:aws:redshift:{region}:{current_aws_account_id}:reserved-node/{reserved_node['ReservedNodeId']}"
        )
        reserved_node["consolelink"] = aws_console_link.get_console_link(arn=reserved_node["arn"])
        reserved_nodes.append(reserved_node)

    return reserved_nodes


def load_redshift_reserved_node(
    session: neo4j.Session, reserved_nodes: List[Dict], current_aws_account_id: str, aws_update_tag: int,
) -> None:
    session.execute_write(_load_redshift_reserved_node_tx, reserved_nodes, current_aws_account_id, aws_update_tag)


@timeit
def _load_redshift_reserved_node_tx(
    tx: neo4j.Transaction,
    data: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_rds_secgroup = """
    UNWIND $reserved_nodes as reserved_node
        MERGE (node:RedshiftReservedNode{id: reserved_node.arn})
        ON CREATE SET node.firstseen = timestamp(),
            node.arn = reserved_node.arn
        SET node.reserved_node_offering_id = reserved_node.ReservedNodeOfferingId,
            node.name = reserved_node.ReservedNodeId,
            node.reserved_node_id = reserved_node.ReservedNodeId,
            node.node_type = reserved_node.NodeType,
            node.start_time = reserved_node.StartTime,
            node.duration = reserved_node.Duration,
            node.fixed_price = reserved_node.FixedPrice,
            node.usage_price = reserved_node.UsagePrice,
            node.currency_code = reserved_node.CurrencyCode,
            node.node_count = reserved_node.NodeCount,
            node.state = reserved_node.State,
            node.offering_type = reserved_node.OfferingType,
            node.reserved_node_offering_type = reserved_node.ReservedNodeOfferingType,
            node.lastupdated = $aws_update_tag
        WITH node
        MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
        MERGE (aa)-[r:RESOURCE]->(node)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_rds_secgroup,
        reserved_nodes=data,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


def cleanup_redshift_reserved_node(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("aws_import_redshift_reserved_nodes_cleanup.json", neo4j_session, common_job_parameters)


@timeit
def sync_redshift_reserved_node(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    data = []
    for region in regions:
        logger.info("Syncing redshift_reserved_node for region '%s' in account '%s'.", region, current_aws_account_id)
        rnodes = get_redshift_reserved_node(boto3_session, region)
        data.extend(transform_reserved_nodes(rnodes, region, current_aws_account_id))

    logger.info(f"Total Redshift Reserved Nodes: {len(data)}")

    load_redshift_reserved_node(neo4j_session, data, current_aws_account_id, update_tag)
    cleanup_redshift_reserved_node(neo4j_session, common_job_parameters)


@timeit
@aws_handle_regions
def get_redshift_cluster_data(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    client = boto3_session.client("redshift", region_name=region, config=get_botocore_config())
    paginator = client.get_paginator("describe_clusters")
    clusters: List[Dict] = []
    for page in paginator.paginate():
        clusters.extend(page["Clusters"])
    for cluster in clusters:
        cluster["region"] = region
    return clusters


def _make_redshift_cluster_arn(region: str, aws_account_id: str, cluster_identifier: str) -> str:
    """Cluster ARN format: https://docs.aws.amazon.com/redshift/latest/mgmt/redshift-iam-access-control-overview.html"""
    return f"arn:aws:redshift:{region}:{aws_account_id}:cluster:{cluster_identifier}"


def transform_redshift_cluster_data(clusters: List[Dict], current_aws_account_id: str) -> None:
    for cluster in clusters:
        cluster["arn"] = _make_redshift_cluster_arn(
            cluster["region"],
            current_aws_account_id,
            cluster["ClusterIdentifier"],
        )
        cluster["ClusterCreateTime"] = str(cluster["ClusterCreateTime"]) if "ClusterCreateTime" in cluster else None


@timeit
def load_redshift_cluster_data(
    neo4j_session: neo4j.Session,
    clusters: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_cluster = """
    UNWIND $DictList AS item
    MERGE (cluster:RedshiftCluster{id: item.arn})
    ON CREATE SET cluster.firstseen = timestamp(),
    cluster.arn = item.arn
    SET cluster.availability_zone = item.az,
    cluster.cluster_create_time = item.cluster_create_time,
    cluster.cluster_identifier = item.cluster_identifier,
    cluster.cluster_revision_number = item.cluster_revision_number,
    cluster.db_name = item.db_name,
    cluster.consolelink = item.consolelink,
    cluster.encrypted = item.encrypted,
    cluster.cluster_status = item.cluster_status,
    cluster.endpoint_address = item.endpoint_address,
    cluster.endpoint_port = item.endpoint_port,
    cluster.master_username = item.master_username,
    cluster.node_type = item.node_type,
    cluster.number_of_nodes = item.number_of_nodes,
    cluster.publicly_accessible = item.publicly_accessible,
    cluster.vpc_id = item.vpc_id,
    cluster.lastupdated = $aws_update_tag,
    cluster.region = item.region
    WITH cluster
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(cluster)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    """

    cluster_rows = []
    for cluster in clusters:
        endpoint = cluster.get("Endpoint") or {}
        cluster_rows.append({
            "arn": cluster["arn"],
            "consolelink": aws_console_link.get_console_link(arn=cluster["arn"]),
            "az": cluster.get("AvailabilityZone"),
            "cluster_create_time": cluster.get("ClusterCreateTime"),
            "cluster_identifier": cluster.get("ClusterIdentifier"),
            "cluster_revision_number": cluster.get("ClusterRevisionNumber"),
            "cluster_status": cluster.get("ClusterStatus"),
            "db_name": cluster.get("DBName"),
            "encrypted": cluster.get("Encrypted"),
            "endpoint_address": endpoint.get("Address", ""),
            "endpoint_port": endpoint.get("Port", ""),
            "master_username": cluster.get("MasterUsername"),
            "node_type": cluster.get("NodeType"),
            "number_of_nodes": cluster.get("NumberOfNodes"),
            "publicly_accessible": cluster.get("PubliclyAccessible"),
            "vpc_id": cluster.get("VpcId"),
            "region": cluster.get("region"),
        })
    load_graph_data(
        neo4j_session, ingest_cluster, cluster_rows,
        AWS_ACCOUNT_ID=current_aws_account_id, aws_update_tag=aws_update_tag,
    )
    _attach_ec2_security_groups(neo4j_session, clusters, aws_update_tag, current_aws_account_id)
    _attach_iam_roles(neo4j_session, clusters, aws_update_tag)
    _attach_aws_vpc(neo4j_session, clusters, aws_update_tag)
    _attach_aws_network_interface(neo4j_session, clusters, aws_update_tag)
    _attach_aws_ec2_subnet(neo4j_session, clusters, aws_update_tag)


@timeit
def _attach_ec2_security_groups(
    neo4j_session: neo4j.Session, clusters: List[Dict], aws_update_tag: int, account_id: str,
) -> None:
    attach_cluster_to_group = """
    UNWIND $DictList AS item
    MATCH (c:RedshiftCluster{id:item.cluster_arn})
    MERGE (sg:EC2SecurityGroup{id:item.group_id})
    SET sg.consolelink = item.consolelink
    MERGE (c)-[m:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
    ON CREATE SET m.firstseen = timestamp()
    SET m.lastupdated = $aws_update_tag
    """
    rows = []
    for cluster in clusters:
        for group in cluster.get("VpcSecurityGroups", []):
            region = group.get("region", "")
            group_id = group.get("GroupId")
            group_arn = f"arn:aws:ec2:{region}:{account_id}:security-group/{group_id}"
            rows.append({
                "cluster_arn": cluster["arn"],
                "consolelink": aws_console_link.get_console_link(arn=group_arn),
                "group_id": group["VpcSecurityGroupId"],
            })
    load_graph_data(neo4j_session, attach_cluster_to_group, rows, aws_update_tag=aws_update_tag)


@timeit
def _attach_iam_roles(neo4j_session: neo4j.Session, clusters: List[Dict], aws_update_tag: int) -> None:
    attach_cluster_to_role = """
    UNWIND $DictList AS item
    MATCH (c:RedshiftCluster{id:item.cluster_arn})
    MERGE (p:AWSPrincipal{arn:item.role_arn})
    MERGE (c)-[s:STS_ASSUMEROLE_ALLOW]->(p)
    ON CREATE SET s.firstseen = timestamp()
    SET s.lastupdated = $aws_update_tag
    """
    rows = [
        {"cluster_arn": cluster["arn"], "role_arn": role["IamRoleArn"]}
        for cluster in clusters
        for role in cluster.get("IamRoles", [])
    ]
    load_graph_data(neo4j_session, attach_cluster_to_role, rows, aws_update_tag=aws_update_tag)


@timeit
def _attach_aws_vpc(neo4j_session: neo4j.Session, clusters: List[Dict], aws_update_tag: int) -> None:
    attach_cluster_to_vpc = """
    UNWIND $DictList AS item
    MATCH (c:RedshiftCluster{id:item.cluster_arn})
    MERGE (v:AWSVpc{id:item.vpc_id})
    MERGE (c)-[m:MEMBER_OF_AWS_VPC]->(v)
    ON CREATE SET m.firstseen = timestamp()
    SET m.lastupdated = $aws_update_tag
    """
    rows = [
        {"cluster_arn": cluster["arn"], "vpc_id": cluster["VpcId"]}
        for cluster in clusters
        if cluster.get("VpcId")
    ]
    load_graph_data(neo4j_session, attach_cluster_to_vpc, rows, aws_update_tag=aws_update_tag)


@timeit
def _attach_aws_network_interface(neo4j_session: neo4j.Session, clusters: List[Dict], aws_update_tag: int) -> None:
    attach_cluster_to_network_interface = """
    UNWIND $DictList AS item
        MATCH (c:RedshiftCluster{id:item.cluster_arn})
        MERGE (v:NetworkInterface{id: item.network_interface_id})
        MERGE (c)-[m:NETWORK_INTERFACE]->(v)
        ON CREATE SET m.firstseen = timestamp()
        SET m.lastupdated = $aws_update_tag
    """
    rows = [
        {"cluster_arn": cluster["arn"], "network_interface_id": nic["NetworkInterfaceId"]}
        for cluster in clusters
        for vpc_endpoint in cluster.get("VpcEndpoints", [])
        for nic in vpc_endpoint["NetworkInterfaces"]
    ]
    load_graph_data(neo4j_session, attach_cluster_to_network_interface, rows, aws_update_tag=aws_update_tag)


@timeit
def _attach_aws_ec2_subnet(neo4j_session: neo4j.Session, clusters: List[Dict], aws_update_tag: int) -> None:
    attach_cluster_to_ec2_subnet = """
    UNWIND $DictList AS item
        MATCH (c:RedshiftCluster{id:item.cluster_arn})
        MERGE (s:EC2Subnet{id: item.subnet_id})
        MERGE (c)-[m:CLUSTER_SUBNET]->(s)
        ON CREATE SET m.firstseen = timestamp()
        SET m.lastupdated = $aws_update_tag
    """
    rows = [
        {"cluster_arn": cluster["arn"], "subnet_id": nic["SubnetId"]}
        for cluster in clusters
        for vpc_endpoint in cluster.get("VpcEndpoints", [])
        for nic in vpc_endpoint["NetworkInterfaces"]
    ]
    load_graph_data(neo4j_session, attach_cluster_to_ec2_subnet, rows, aws_update_tag=aws_update_tag)


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("aws_import_redshift_clusters_cleanup.json", neo4j_session, common_job_parameters)


@timeit
def sync_redshift_clusters(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    regions: str,
    current_aws_account_id: str,
    aws_update_tag: int,
    common_job_parameters: Dict,
) -> None:
    data = []
    for region in regions:
        data.extend(get_redshift_cluster_data(boto3_session, region))

    logger.info(f"Total Redshift Clusters: {len(data)}")

    transform_redshift_cluster_data(data, current_aws_account_id)
    load_redshift_cluster_data(neo4j_session, data, current_aws_account_id, aws_update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session,
    boto3_session: boto3.session.Session,
    regions: List[str],
    current_aws_account_id: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing Redshift clusters for account '%s', at %s.", current_aws_account_id, tic)
    sync_redshift_clusters(
        neo4j_session,
        boto3_session,
        regions,
        current_aws_account_id,
        update_tag,
        common_job_parameters,
    )
    sync_redshift_reserved_node(
        neo4j_session,
        boto3_session,
        regions,
        current_aws_account_id,
        update_tag,
        common_job_parameters,
    )
    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Redshift clusters: {toc - tic:0.4f} seconds")
