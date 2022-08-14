import cartography.intel.aws.rds
from tests.data.aws.rds import DESCRIBE_DBCLUSTERS_RESPONSE
from tests.data.aws.rds import DESCRIBE_DBINSTANCES_RESPONSE
from tests.data.aws.rds import DESCRIBE_SECURITY_GROUPS_RESPONSE
from tests.data.aws.rds import DESCRIBE_SNAPSHOTS_RESPONSE
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
        "arn:aws:rds:us-east-1:123456789012:snapshot:mydbsnapshot",
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
        neo4j_session,
        DESCRIBE_SNAPSHOTS_RESPONSE,
        '123456789012',
        TEST_UPDATE_TAG,
    )
