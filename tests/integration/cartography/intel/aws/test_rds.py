import cartography.intel.aws.rds
from cartography.util import run_analysis_job
from tests.data.aws.ec2.route_tables import DESCRIBE_ROUTE_TABLES
from tests.data.aws.ec2.security_groups import DESCRIBE_SGS
from tests.data.aws.ec2.subnets import DESCRIBE_SUBNETS
from tests.data.aws.rds import DESCRIBE_DBCLUSTERS_RESPONSE
from tests.data.aws.rds import DESCRIBE_DBINSTANCES_RESPONSE
from tests.data.aws.rds import DESCRIBE_DBSNAPSHOT_ATTRIBUTE_RESPONSE
from tests.data.aws.rds import DESCRIBE_DBSNAPSHOTS_RESPONSE
from tests.data.aws.rds import DESCRIBE_SECURITY_GROUPS_RESPONSE
from tests.integration.cartography.intel.aws.common import create_exposure_test_account

TEST_UPDATE_TAG = 123456789


def test_load_rds_clusters_basic(neo4j_session):
    """Test that we successfully load RDS cluster nodes to the graph"""
    cartography.intel.aws.rds.load_rds_clusters(
        neo4j_session,
        DESCRIBE_DBCLUSTERS_RESPONSE['DBClusters'],
        '1234',
        TEST_UPDATE_TAG,
    )
    query = """MATCH(rds:RDSCluster) RETURN rds.id, rds.arn, rds.storage_encrypted"""
    nodes = neo4j_session.run(query)

    actual_nodes = {(n['rds.id'], n['rds.arn'], n['rds.storage_encrypted']) for n in nodes}
    expected_nodes = {
        (
            'arn:aws:rds:us-east-1:some-arn:cluster:some-prod-db-iad-0',
            'arn:aws:rds:us-east-1:some-arn:cluster:some-prod-db-iad-0',
            True,
        ),
    }
    assert actual_nodes == expected_nodes

    cartography.intel.aws.rds.load_rds_instances(
        neo4j_session,
        DESCRIBE_DBINSTANCES_RESPONSE['DBInstances'],
        '1234',
        TEST_UPDATE_TAG,
    )

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (r:RDSInstance)-[:IS_CLUSTER_MEMBER_OF]->(c:RDSCluster)
        RETURN r.db_cluster_identifier, c.db_cluster_identifier;
        """,
    )
    expected = {
        (
            'some-prod-db-iad',
            'some-prod-db-iad',
        ),
    }

    actual = {
        (r['r.db_cluster_identifier'], r['c.db_cluster_identifier']) for r in result
    }

    assert actual == expected

    # Cleanup to not interfere with other rds tests
    result = neo4j_session.run(
        """
        MATCH (r:RDSInstance)
        DETACH DELETE r
        """,
    )


def test_load_rds_instances_basic(neo4j_session):
    """Test that we successfully load RDS instance nodes to the graph"""
    cartography.intel.aws.rds.load_rds_instances(
        neo4j_session,
        DESCRIBE_DBINSTANCES_RESPONSE['DBInstances'],
        '1234',
        TEST_UPDATE_TAG,
    )
    query = """MATCH(rds:RDSInstance) RETURN rds.id, rds.arn, rds.storage_encrypted"""
    nodes = neo4j_session.run(query)

    actual_nodes = {(n['rds.id'], n['rds.arn'], n['rds.storage_encrypted']) for n in nodes}
    expected_nodes = {
        (
            'arn:aws:rds:us-east-1:some-arn:db:some-prod-db-iad-0',
            'arn:aws:rds:us-east-1:some-arn:db:some-prod-db-iad-0',
            True,
        ),
    }
    assert actual_nodes == expected_nodes


def test_load_rds_security_group_data(neo4j_session):
    _ensure_local_neo4j_has_test_rds_security_group_data(neo4j_session)
    expected_nodes = {
        "arn:aws:rds:us-east-1:111122223333:secgrp:mysecgroup",
    }
    nodes = neo4j_session.run(
        """
        MATCH (n:RDSSecurityGroup) RETURN n.id;
        """,
    )
    actual_nodes = {n['n.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def _ensure_local_neo4j_has_test_rds_security_group_data(neo4j_session):
    cartography.intel.aws.rds.load_rds_security_groups(
        neo4j_session,
        DESCRIBE_SECURITY_GROUPS_RESPONSE,
        '111122223333',
        TEST_UPDATE_TAG,
    )


def test_load_rds_snapshots_data(neo4j_session):
    _ensure_local_neo4j_has_test_rds_snapshots_data(neo4j_session)
    expected_nodes = {
        'arn:aws:rds:us-east-1:some-arn:snapshot:some-prod-db-iad-0',
        'arn:aws:rds:us-east-2:some-arn:snapshot:some-prod-db-iad-0',
    }
    nodes = neo4j_session.run(
        """
        MATCH (n:RDSSnapshot) RETURN n.id;
        """,
    )
    actual_nodes = {n['n.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def _ensure_local_neo4j_has_test_rds_snapshots_data(neo4j_session):
    cartography.intel.aws.rds.load_rds_snapshots(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBSNAPSHOTS_RESPONSE['DBSnapshots'],
        current_aws_account_id='123456789012',
        aws_update_tag=TEST_UPDATE_TAG,
    )


def test_load_rds_snapshots_basic(neo4j_session):
    """Test that we successfully load RDS snapshots to the graph"""
    cartography.intel.aws.rds.load_rds_instances(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBINSTANCES_RESPONSE['DBInstances'],
        current_aws_account_id='1234',
        aws_update_tag=TEST_UPDATE_TAG,
    )
    cartography.intel.aws.rds.load_rds_snapshots(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBSNAPSHOTS_RESPONSE['DBSnapshots'],
        current_aws_account_id='1234',
        aws_update_tag=TEST_UPDATE_TAG,
    )

    query = """MATCH(rds:RDSSnapshot) RETURN rds.id, rds.arn, rds.db_snapshot_identifier, rds.db_instance_identifier"""
    snapshots = neo4j_session.run(query)

    actual_snapshots = {
        (n['rds.id'], n['rds.arn'], n['rds.db_snapshot_identifier'], n['rds.db_instance_identifier']) for n in snapshots
    }
    expected_snapshots = {
        (
            'arn:aws:rds:us-east-1:some-arn:snapshot:some-prod-db-iad-0',
            'arn:aws:rds:us-east-1:some-arn:snapshot:some-prod-db-iad-0',
            'some-db-snapshot-identifier',
            'some-prod-db-iad-0',
        ),
        (
            'arn:aws:rds:us-east-2:some-arn:snapshot:some-prod-db-iad-0',
            'arn:aws:rds:us-east-2:some-arn:snapshot:some-prod-db-iad-0',
            'some-other-db-snapshot-identifier',
            'some-prod-db-iad-0',
        ),
    }
    assert actual_snapshots == expected_snapshots

    query = """MATCH(rdsInstance:RDSInstance)-[:IS_SNAPSHOT_SOURCE]-(rdsSnapshot:RDSSnapshot)
               RETURN rdsInstance.id, rdsSnapshot.id"""
    results = neo4j_session.run(query)

    actual_results = {
        (n['rdsInstance.id'], n['rdsSnapshot.id']) for n in results
    }
    expected_results = {
        (
            'arn:aws:rds:us-east-1:some-arn:db:some-prod-db-iad-0',
            'arn:aws:rds:us-east-1:some-arn:snapshot:some-prod-db-iad-0',
        ),
        (
            'arn:aws:rds:us-east-1:some-arn:db:some-prod-db-iad-0',
            'arn:aws:rds:us-east-2:some-arn:snapshot:some-prod-db-iad-0',
        ),
    }
    assert actual_results == expected_results


def test_snapshot_attributes(neo4j_session):
    cartography.intel.aws.rds.load_rds_instances(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBINSTANCES_RESPONSE['DBInstances'],
        current_aws_account_id='1234',
        aws_update_tag=TEST_UPDATE_TAG,
    )
    cartography.intel.aws.rds.load_rds_snapshots(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBSNAPSHOTS_RESPONSE['DBSnapshots'],
        current_aws_account_id='1234',
        aws_update_tag=TEST_UPDATE_TAG,
    )
    cartography.intel.aws.rds.load_rds_snapshot_attributes(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBSNAPSHOT_ATTRIBUTE_RESPONSE,
        aws_update_tag=TEST_UPDATE_TAG,
    )

    query = """MATCH (attr:RDSSnapshotAttribute)<-[:HAS_ATTRIBUTE]-(rds:RDSSnapshot) RETURN attr.name, rds.id"""
    snapshots_attribs = neo4j_session.run(query)

    actual_nodes = {
        (n['rds.id'], n['attr.name']) for n in snapshots_attribs
    }

    expected_nodes = {
        (
            'arn:aws:rds:us-east-1:some-arn:snapshot:some-prod-db-iad-0',
            'attrib-1',
        ),
        (
            'arn:aws:rds:us-east-1:some-arn:snapshot:some-prod-db-iad-0',
            'backup',
        ),
        (
            'arn:aws:rds:us-east-2:some-arn:snapshot:some-prod-db-iad-0',
            'attrib-1',
        ),
        (
            'arn:aws:rds:us-east-2:some-arn:snapshot:some-prod-db-iad-0',
            'backup',
        ),
        (
            'arn:aws:rds:us-east-2:some-arn:snapshot:some-prod-db-iad-0',
            'restore',
        ),
    }

    assert actual_nodes == expected_nodes


def test_rds_exposure(neo4j_session):
    neo4j_session.run(
        """
        MERGE (aws:AWSAccount{id: $aws_account_id})<-[:OWNER]-(:CloudanixWorkspace{id: $workspace_id})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        aws_account_id='1234',
        aws_update_tag=TEST_UPDATE_TAG,
        workspace_id='1234',
    )

    cartography.intel.aws.ec2.route_tables.load_route_tables(
        neo4j_session,
        DESCRIBE_ROUTE_TABLES,
        '1234',
        TEST_UPDATE_TAG,
    )
    cartography.intel.aws.ec2.subnets.load_subnets(
        neo4j_session,
        DESCRIBE_SUBNETS,
        '1234',
        TEST_UPDATE_TAG,
    )

    cartography.intel.aws.ec2.security_groups.load_ec2_security_groupinfo(
        neo4j_session,
        DESCRIBE_SGS,
        '1234',
        TEST_UPDATE_TAG,
    )

    cartography.intel.aws.rds.load_rds_instances(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBINSTANCES_RESPONSE['DBInstances'],
        current_aws_account_id='1234',
        aws_update_tag=TEST_UPDATE_TAG,
    )
    cartography.intel.aws.rds.load_rds_snapshots(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBSNAPSHOTS_RESPONSE['DBSnapshots'],
        current_aws_account_id='1234',
        aws_update_tag=TEST_UPDATE_TAG,
    )
    cartography.intel.aws.rds.load_rds_snapshot_attributes(
        neo4j_session=neo4j_session,
        data=DESCRIBE_DBSNAPSHOT_ATTRIBUTE_RESPONSE,
        aws_update_tag=TEST_UPDATE_TAG,
    )
    common_job_parameters = {
        "UPDATE_TAG": TEST_UPDATE_TAG + 1,
        "WORKSPACE_ID": '1234',
        "AWS_ID": '1234',
    }

    run_analysis_job(
        'aws_ec2_subnet_asset_exposure.json',
        neo4j_session,
        common_job_parameters,
    )

    run_analysis_job(
        'aws_rds_asset_exposure.json',
        neo4j_session,
        common_job_parameters,
    )

    query = """MATCH (rds:RDSInstance{exposed_internet: true}) RETURN rds.id, rds.exposed_internet_type"""
    rds = neo4j_session.run(query)

    actual_nodes = {
        (n['rds.id'], ",".join(n['rds.exposed_internet_type'])) for n in rds
    }

    expected_nodes = {
        (
            'arn:aws:rds:us-east-1:some-arn:db:some-prod-db-iad-0',
            'direct_ipv4,public_subnet',
        ),
    }

    assert actual_nodes == expected_nodes

    query = """MATCH (rds:RDSSnapshot{exposed_internet: true}) RETURN rds.id, rds.exposed_internet_type"""
    rds = neo4j_session.run(query)

    actual_nodes = {
        (n['rds.id'], ",".join(n['rds.exposed_internet_type'])) for n in rds
    }

    expected_nodes = {
        (
            'arn:aws:rds:us-east-2:some-arn:snapshot:some-prod-db-iad-0',
            'restore_all_attrib',
        ),
    }

    assert actual_nodes == expected_nodes


RESET_ACCOUNT_ID = '222233334444'
RESET_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG + 1,
    'AWS_ID': RESET_ACCOUNT_ID,
    'ORGANIZATION_ID': 'o-rds-reset',
    'WORKSPACE_ID': 'ws-rds-reset',
    'LIMIT_SIZE': 100,
}


def test_rds_exposure_resets_stale_flags(neo4j_session):
    create_exposure_test_account(
        neo4j_session, RESET_JOB_PARAMETERS['WORKSPACE_ID'], RESET_JOB_PARAMETERS['ORGANIZATION_ID'],
        RESET_ACCOUNT_ID,
    )
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (sg:EC2SecurityGroup{id: 'sg-rds-reset-open'})
        MERGE (:IpRange{id: '0.0.0.0/0', range: '0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->
              (:IpPermissionInbound{ruleid: 'sg-rds-reset-open/tcp/5432'})-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        WITH aa, sg
        UNWIND $dbs AS d
        MERGE (aa)-[:RESOURCE]->(rds:RDSInstance{id: d.id})
        SET rds.publicly_accessible = d.pa, rds.exposed_internet = d.stale,
            rds.exposed_internet_type = CASE WHEN d.stale THEN ['direct_ipv4'] END
        MERGE (rds)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        """,
        account_id=RESET_ACCOUNT_ID, dbs=[
            # Flagged by an earlier job version (SG rule alone); not publicly accessible, so no public address.
            {'id': 'rds-reset-private-stale', 'pa': False, 'stale': True},
            {'id': 'rds-reset-public', 'pa': True, 'stale': True},
        ],
    )
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (aa)-[:RESOURCE]->(s:RDSSnapshot{id: 'rds-reset-snapshot-stale'})
        SET s.exposed_internet = true, s.exposed_internet_type = ['restore_all_attrib']
        MERGE (aa)-[:RESOURCE]->(other:EC2Instance{id: 'rds-reset-other-label'})
        SET other.exposed_internet = true
        """,
        account_id=RESET_ACCOUNT_ID,
    )

    run_analysis_job('aws_rds_asset_exposure.json', neo4j_session, RESET_JOB_PARAMETERS)

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(n{exposed_internet: true})
        RETURN n.id AS id, n.exposed_internet_type AS types
        """,
        account_id=RESET_ACCOUNT_ID,
    )
    assert {n['id']: sorted(n['types'] or []) for n in nodes} == {
        'rds-reset-public': ['direct', 'direct_ipv4'],
        # The reset only touches RDS instances and snapshots.
        'rds-reset-other-label': [],
    }
