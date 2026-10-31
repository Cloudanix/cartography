from unittest.mock import MagicMock

import cartography.intel.aws.rds
import cartography.intel.aws.resourcegroupstaggingapi as rgta
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777775'
REGION = 'us-east-1'


def _cluster_arn(name):
    return f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:cluster:{name}'


def _cluster(name, engine):
    # Shape of one DescribeDBClusters DBCluster.
    return {
        'DBClusterArn': _cluster_arn(name), 'DBClusterIdentifier': name, 'Engine': engine, 'Port': 8182,
        'Endpoint': f'{name}.cluster-x.{REGION}.neptune.amazonaws.com', 'DBSubnetGroup': f'{name}-subnets',
        'VpcSecurityGroups': [{'VpcSecurityGroupId': f'{name}-sg', 'Status': 'active'}],
        'DBClusterMembers': [{'DBInstanceIdentifier': f'{name}-1', 'IsClusterWriter': True}],
        'IAMDatabaseAuthenticationEnabled': True, 'StorageEncrypted': True,
    }


def _instance(name, engine, cluster):
    # Shape of one DescribeDBInstances DBInstance after get_rds_instance_data.
    return {
        'DBInstanceArn': f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:db:{name}', 'DBInstanceIdentifier': name,
        'Engine': engine, 'DBClusterIdentifier': cluster, 'PubliclyAccessible': False, 'region': REGION,
        'Endpoint': {'Address': f'{name}.x.{REGION}.neptune.amazonaws.com', 'Port': 8182},
    }


def test_neptune_clusters_are_split_from_rds_clusters(neo4j_session, mocker):
    create_test_org_account(neo4j_session, 'ws-npt', 'o-npt', ACCOUNT_ID)
    # Before the split the RDS sync stored Neptune clusters as RDSCluster nodes.
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        MERGE (a)-[:RESOURCE]->(old:RDSCluster{id: $arn})
        SET old.lastupdated = $old_tag, old.db_cluster_identifier = 'npt-graph', old.engine = 'neptune'
        """,
        account_id=ACCOUNT_ID, arn=_cluster_arn('npt-graph'), old_tag=TEST_UPDATE_TAG - 1,
    )
    mocker.patch.object(cartography.intel.aws.rds, 'dns_lookup_with_ip_type', return_value=[])
    mocker.patch.object(
        cartography.intel.aws.rds, 'get_rds_cluster_data',
        return_value=[_cluster('npt-graph', 'neptune'), _cluster('npt-aurora', 'aurora-postgresql')],
    )
    params = exposure_job_parameters('ws-npt', 'o-npt', ACCOUNT_ID, TEST_UPDATE_TAG)

    cartography.intel.aws.rds.sync_rds_clusters(
        neo4j_session, MagicMock(), [REGION], ACCOUNT_ID, TEST_UPDATE_TAG, params,
    )
    cartography.intel.aws.rds.load_rds_instances(
        neo4j_session,
        [
            _instance('npt-graph-1', 'neptune', 'npt-graph'),
            _instance('npt-aurora-1', 'aurora-postgresql', 'npt-aurora'),
        ],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.rds.load_rds_cluster_snapshots(
        neo4j_session,
        [{
            'DBClusterSnapshotArn': f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:cluster-snapshot:npt-graph-snap',
            'DBClusterIdentifier': 'npt-graph', 'Engine': 'neptune', 'region': REGION,
        }],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    rgta.load_tags(
        neo4j_session,
        [
            {'resource_id': _cluster_arn(name), 'Tags': [{'Key': 'env', 'Value': f'npt-{name}'}]}
            for name in ('npt-graph', 'npt-aurora')
        ],
        'rds:cluster', REGION, ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    rows = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(c)
        WHERE c:RDSCluster OR c:NeptuneCluster
        OPTIONAL MATCH (member:RDSInstance)-[:IS_CLUSTER_MEMBER_OF]->(c)
        OPTIONAL MATCH (c)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
        OPTIONAL MATCH (c)-[:MEMBER_OF_DB_SUBNET_GROUP]->(sng:DBSubnetGroup)
        OPTIONAL MATCH (c)-[:IS_SNAPSHOT_SOURCE]->(snap:RDSClusterSnapshot)
        OPTIONAL MATCH (c)-[:TAGGED]->(tag:AWSTag)
        RETURN c.db_cluster_identifier AS name, labels(c) AS labels, c.port AS port,
            c.iam_database_authentication_enabled AS iam_auth, c.members AS members,
            collect(DISTINCT member.db_instance_identifier) AS member_instances, collect(DISTINCT sg.id) AS groups,
            collect(DISTINCT sng.id) AS subnet_groups, collect(DISTINCT snap.id) AS snapshots,
            collect(DISTINCT tag.value) AS tags
        """,
        account_id=ACCOUNT_ID,
    )
    clusters = {r['name']: r for r in rows}

    # One node per cluster: the stale RDSCluster copy of the Neptune cluster is cleaned up.
    assert {name: r['labels'] for name, r in clusters.items()} == {
        'npt-graph': ['NeptuneCluster'], 'npt-aurora': ['RDSCluster'],
    }
    graph = clusters['npt-graph']
    assert (graph['port'], graph['iam_auth'], graph['members'], graph['member_instances']) == (
        8182, True, ['npt-graph-1'], ['npt-graph-1'],
    )
    assert graph['groups'] == ['npt-graph-sg']
    assert graph['subnet_groups'] == [f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:subgrp:npt-graph-subnets']
    assert graph['snapshots'] == [f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:cluster-snapshot:npt-graph-snap']
    assert graph['tags'] == ['npt-npt-graph']
    # RDS clusters keep their members and tags.
    assert (clusters['npt-aurora']['member_instances'], clusters['npt-aurora']['tags']) == (
        ['npt-aurora-1'], ['npt-npt-aurora'],
    )
