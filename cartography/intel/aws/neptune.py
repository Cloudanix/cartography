"""
Amazon Neptune DB clusters.

Neptune is managed through the RDS API: rds:DescribeDBClusters returns Neptune clusters next to the RDS ones
(engine 'neptune'), and rds:DescribeDBInstances returns their instances. The RDS sync makes those calls once and
hands the Neptune clusters here, so they become NeptuneCluster nodes instead of RDSCluster nodes: one asset under the
console's Neptune DB cluster type, not an RDS cluster. Neptune instances stay RDSInstance nodes and are linked to
their cluster here.
"""
import logging
from typing import Dict
from typing import List

import neo4j

from cartography.client.core.tx import load_graph_data
from cartography.intel.aws.util.arns import DEFAULT_PARTITION
from cartography.util import dict_value_to_str
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

NEPTUNE_ENGINE = 'neptune'


def is_neptune(db_item: Dict) -> bool:
    """True for a DBCluster or DBInstance of the Neptune engine."""
    return db_item.get('Engine') == NEPTUNE_ENGINE


@timeit
def load_neptune_clusters(
    neo4j_session: neo4j.Session, clusters: List[Dict], current_aws_account_id: str, update_tag: int,
    partition: str = DEFAULT_PARTITION,
) -> None:
    """
    clusters are rds.transform_clusters() output (DBCluster dicts with region, name, consolelink, privateIp, publicIp).
    """
    query = """
    UNWIND $DictList AS item
        MERGE (cluster:NeptuneCluster{id: item.DBClusterArn})
        ON CREATE SET cluster.firstseen = timestamp(),
            cluster.arn = item.DBClusterArn
        SET cluster.lastupdated = $aws_update_tag,
            cluster.name = item.name,
            cluster.db_cluster_identifier = item.DBClusterIdentifier,
            cluster.db_cluster_resource_id = item.DbClusterResourceId,
            cluster.engine = item.Engine,
            cluster.engine_version = item.EngineVersion,
            cluster.status = item.Status,
            cluster.endpoint = item.Endpoint,
            cluster.reader_endpoint = item.ReaderEndpoint,
            cluster.port = item.Port,
            cluster.privateIp = item.privateIp,
            cluster.publicIp = item.publicIp,
            cluster.multi_az = item.MultiAZ,
            cluster.availability_zones = item.AvailabilityZones,
            cluster.storage_encrypted = item.StorageEncrypted,
            cluster.kms_key_id = item.KmsKeyId,
            cluster.iam_database_authentication_enabled = item.IAMDatabaseAuthenticationEnabled,
            cluster.deletion_protection = item.DeletionProtection,
            cluster.backup_retention_period = item.BackupRetentionPeriod,
            cluster.preferred_backup_window = item.PreferredBackupWindow,
            cluster.preferred_maintenance_window = item.PreferredMaintenanceWindow,
            cluster.copy_tags_to_snapshot = item.CopyTagsToSnapshot,
            cluster.enabled_cloudwatch_logs_exports = item.EnabledCloudwatchLogsExports,
            cluster.db_subnet_group = item.DBSubnetGroup,
            cluster.db_parameter_group = item.DBClusterParameterGroup,
            cluster.security_groups = item.security_groups,
            cluster.members = item.members,
            cluster.master_username = item.MasterUsername,
            cluster.hosted_zone_id = item.HostedZoneId,
            cluster.cluster_create_time = item.cluster_create_time,
            cluster.region = item.region,
            cluster.consolelink = item.consolelink
        WITH cluster
        MATCH (owner:AWSAccount{id: $aws_account_id})
        MERGE (owner)-[r:RESOURCE]->(cluster)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    for cluster in clusters:
        cluster['security_groups'] = [g['VpcSecurityGroupId'] for g in cluster.get('VpcSecurityGroups') or []]
        cluster['members'] = [m['DBInstanceIdentifier'] for m in cluster.get('DBClusterMembers') or []]
        cluster['cluster_create_time'] = dict_value_to_str(cluster, 'ClusterCreateTime')
    logger.info(f"Loading {len(clusters)} Neptune clusters into graph.")
    load_graph_data(
        neo4j_session, query, clusters, aws_update_tag=update_tag, aws_account_id=current_aws_account_id,
    )
    _attach_security_groups(neo4j_session, clusters, update_tag)
    _attach_db_subnet_groups(neo4j_session, clusters, current_aws_account_id, update_tag, partition)


@timeit
def _attach_security_groups(neo4j_session: neo4j.Session, clusters: List[Dict], update_tag: int) -> None:
    # The group node may not be synced yet (services run in parallel); MERGE it like the RDS cluster sync does.
    query = """
    UNWIND $DictList AS item
        MATCH (cluster:NeptuneCluster{id: item.arn})
        MERGE (sg:EC2SecurityGroup{id: item.group_id})
        ON CREATE SET sg.firstseen = timestamp()
        MERGE (cluster)-[r:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    rows = [{'arn': c['DBClusterArn'], 'group_id': group_id} for c in clusters for group_id in c['security_groups']]
    load_graph_data(neo4j_session, query, rows, aws_update_tag=update_tag)


@timeit
def _attach_db_subnet_groups(
    neo4j_session: neo4j.Session, clusters: List[Dict], current_aws_account_id: str, update_tag: int,
    partition: str,
) -> None:
    # DBCluster only names its subnet group; DBSubnetGroup ids are ARNs (see rds._get_db_subnet_group_arn), and the
    # RDS instance sync fills in the group and its subnets.
    query = """
    UNWIND $DictList AS item
        MATCH (cluster:NeptuneCluster{id: item.arn})
        MERGE (sng:DBSubnetGroup{id: item.subnet_group_arn})
        ON CREATE SET sng.firstseen = timestamp(), sng.arn = item.subnet_group_arn, sng.name = item.name
        MERGE (cluster)-[r:MEMBER_OF_DB_SUBNET_GROUP]->(sng)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    rows = []
    for c in clusters:
        if not c.get('DBSubnetGroup'):
            continue
        subnet_group_arn = f"arn:{partition}:rds:{c['region']}:{current_aws_account_id}:subgrp:{c['DBSubnetGroup']}"
        rows.append({'arn': c['DBClusterArn'], 'name': c['DBSubnetGroup'], 'subnet_group_arn': subnet_group_arn})
    load_graph_data(neo4j_session, query, rows, aws_update_tag=update_tag)


@timeit
def attach_member_instances(
    neo4j_session: neo4j.Session, instances: List[Dict], current_aws_account_id: str, update_tag: int,
) -> None:
    """
    Link Neptune instances (RDSInstance nodes) to their cluster in the same account and region: cluster identifiers
    are unique only within one.
    """
    query = """
    UNWIND $DictList AS item
        MATCH (account:AWSAccount{id: $aws_account_id})-[:RESOURCE]->(member:RDSInstance{id: item.DBInstanceArn})
        MATCH (account)-[:RESOURCE]->(cluster:NeptuneCluster{
            db_cluster_identifier: item.DBClusterIdentifier, region: item.region
        })
        MERGE (member)-[r:IS_CLUSTER_MEMBER_OF]->(cluster)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $aws_update_tag
    """
    rows = [
        {'DBInstanceArn': i['DBInstanceArn'], 'DBClusterIdentifier': i['DBClusterIdentifier'], 'region': i['region']}
        for i in instances if is_neptune(i) and i.get('DBClusterIdentifier')
    ]
    load_graph_data(neo4j_session, query, rows, aws_update_tag=update_tag, aws_account_id=current_aws_account_id)


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_neptune_cleanup.json', neo4j_session, common_job_parameters)
