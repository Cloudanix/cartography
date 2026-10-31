import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.intel.aws.util.arns import get_partition_from_params
from cartography.util import aws_handle_regions
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


@timeit
@aws_handle_regions
def get_msk_clusters(boto3_session: boto3.session.Session, region: str) -> List[Dict]:
    """
    ListClustersV2 returns provisioned and serverless clusters with their network and security settings,
    so no per-cluster describe is needed.
    """
    client = boto3_session.client('kafka', region_name=region, config=get_botocore_config())
    clusters: List[Dict] = []
    for page in client.get_paginator('list_clusters_v2').paginate():
        clusters.extend(page.get('ClusterInfoList', []))
    return clusters


def _enabled(auth: Dict, *path: str) -> bool:
    for key in path:
        auth = auth.get(key) or {}
    return bool(auth.get('Enabled'))


@timeit
def transform_msk_clusters(clusters: List[Dict], region: str) -> List[Dict]:
    transformed: List[Dict] = []
    for cluster in clusters:
        provisioned = cluster.get('Provisioned') or {}
        serverless = cluster.get('Serverless') or {}
        broker_group = provisioned.get('BrokerNodeGroupInfo') or {}
        connectivity = broker_group.get('ConnectivityInfo') or {}
        auth = provisioned.get('ClientAuthentication') or serverless.get('ClientAuthentication') or {}
        encryption = provisioned.get('EncryptionInfo') or {}
        in_transit = encryption.get('EncryptionInTransit') or {}
        vpc_configs = serverless.get('VpcConfigs') or []
        transformed.append({
            'ClusterArn': cluster['ClusterArn'],
            'ClusterName': cluster.get('ClusterName'),
            'ClusterType': cluster.get('ClusterType'),
            'State': cluster.get('State'),
            'CurrentVersion': cluster.get('CurrentVersion'),
            'CreationTime': str(cluster['CreationTime']) if cluster.get('CreationTime') else None,
            'KafkaVersion': (provisioned.get('CurrentBrokerSoftwareInfo') or {}).get('KafkaVersion'),
            'InstanceType': broker_group.get('InstanceType'),
            'NumberOfBrokerNodes': provisioned.get('NumberOfBrokerNodes'),
            # Only provisioned clusters have public access; serverless clusters are reachable from their VPCs only.
            'PublicAccessType': (connectivity.get('PublicAccess') or {}).get('Type'),
            'SecurityGroups': broker_group.get('SecurityGroups') or [
                group for config in vpc_configs for group in config.get('SecurityGroupIds') or []
            ],
            'SubnetIds': broker_group.get('ClientSubnets') or [
                subnet for config in vpc_configs for subnet in config.get('SubnetIds') or []
            ],
            'IamAuth': _enabled(auth, 'Sasl', 'Iam'),
            'ScramAuth': _enabled(auth, 'Sasl', 'Scram'),
            'TlsAuth': _enabled(auth, 'Tls'),
            'UnauthenticatedAccess': _enabled(auth, 'Unauthenticated'),
            'ClientBrokerEncryption': in_transit.get('ClientBroker'),
            'InClusterEncryption': in_transit.get('InCluster'),
            'KmsKeyId': (encryption.get('EncryptionAtRest') or {}).get('DataVolumeKMSKeyId'),
            'EnhancedMonitoring': provisioned.get('EnhancedMonitoring'),
            'region': region,
            'consolelink': aws_console_link.get_console_link(arn=cluster['ClusterArn']),
        })
    return transformed


@timeit
def load_msk_clusters(
    neo4j_session: neo4j.Session, clusters: List[Dict], current_aws_account_id: str, update_tag: int,
) -> None:
    query = """
    UNWIND $DictList AS item
        MERGE (cluster:MSKCluster{id: item.ClusterArn})
        ON CREATE SET cluster.firstseen = timestamp(),
            cluster.arn = item.ClusterArn
        SET cluster.lastupdated = $aws_update_tag,
            cluster.name = item.ClusterName,
            cluster.cluster_type = item.ClusterType,
            cluster.state = item.State,
            cluster.current_version = item.CurrentVersion,
            cluster.creation_time = item.CreationTime,
            cluster.kafka_version = item.KafkaVersion,
            cluster.instance_type = item.InstanceType,
            cluster.number_of_broker_nodes = item.NumberOfBrokerNodes,
            cluster.public_access_type = item.PublicAccessType,
            cluster.security_groups = item.SecurityGroups,
            cluster.subnet_ids = item.SubnetIds,
            cluster.iam_auth_enabled = item.IamAuth,
            cluster.scram_auth_enabled = item.ScramAuth,
            cluster.tls_auth_enabled = item.TlsAuth,
            cluster.unauthenticated_access_enabled = item.UnauthenticatedAccess,
            cluster.client_broker_encryption = item.ClientBrokerEncryption,
            cluster.in_cluster_encryption = item.InClusterEncryption,
            cluster.kms_key_id = item.KmsKeyId,
            cluster.enhanced_monitoring = item.EnhancedMonitoring,
            cluster.region = item.region,
            cluster.consolelink = item.consolelink
        WITH cluster
        MATCH (owner:AWSAccount{id: $aws_account_id})
        MERGE (owner)-[r:RESOURCE]->(cluster)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    logger.info(f"Loading {len(clusters)} MSK clusters into graph.")
    load_graph_data(
        neo4j_session, query, clusters, aws_update_tag=update_tag, aws_account_id=current_aws_account_id,
    )
    _attach_security_groups(neo4j_session, clusters, update_tag)
    _attach_subnets(neo4j_session, clusters, update_tag)


@timeit
def _attach_security_groups(neo4j_session: neo4j.Session, clusters: List[Dict], update_tag: int) -> None:
    # The group node may not be synced yet (services run in parallel); MERGE it like RDS and ElastiCache do.
    query = """
    UNWIND $DictList AS item
        MATCH (cluster:MSKCluster{id: item.arn})
        MERGE (sg:EC2SecurityGroup{id: item.group_id})
        ON CREATE SET sg.firstseen = timestamp()
        MERGE (cluster)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    rows = [{'arn': c['ClusterArn'], 'group_id': group_id} for c in clusters for group_id in c['SecurityGroups']]
    load_graph_data(neo4j_session, query, rows, aws_update_tag=update_tag)


@timeit
def _attach_subnets(neo4j_session: neo4j.Session, clusters: List[Dict], update_tag: int) -> None:
    query = """
    UNWIND $DictList AS item
        MATCH (cluster:MSKCluster{id: item.arn}), (subnet:EC2Subnet{subnetid: item.subnet_id})
        MERGE (cluster)-[r:PART_OF_SUBNET]->(subnet)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    rows = [{'arn': c['ClusterArn'], 'subnet_id': subnet_id} for c in clusters for subnet_id in c['SubnetIds']]
    load_graph_data(neo4j_session, query, rows, aws_update_tag=update_tag)


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_msk_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing MSK for account '%s', at %s.", current_aws_account_id, tic)

    partition = get_partition_from_params(common_job_parameters)
    # botocore's bundled endpoint data lists the regions MSK runs in, without an API call.
    msk_regions = set(boto3_session.get_available_regions('kafka', partition_name=partition))
    clusters: List[Dict] = []
    for region in regions:
        if region not in msk_regions:
            continue
        logger.info("Syncing MSK clusters for region '%s' in account '%s'.", region, current_aws_account_id)
        clusters.extend(transform_msk_clusters(get_msk_clusters(boto3_session, region), region))

    load_msk_clusters(neo4j_session, clusters, current_aws_account_id, update_tag)
    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process MSK: {toc - tic:0.4f} seconds")
