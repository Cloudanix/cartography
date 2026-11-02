from cartography.intel.aws import rds
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777801'
OTHER_ACCOUNT_ID = '888888888801'
REGION = 'us-east-1'


def _arn(account_id, kind, name, region=REGION):
    return f'arn:aws:rds:{region}:{account_id}:{kind}:{name}'


def _seed(neo4j_session):
    # "database-1" / "default" are console defaults: every tenant has them.
    create_test_org_account(neo4j_session, 'ws-rds', 'o-rds', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-rds-other', 'o-rds-other', OTHER_ACCOUNT_ID)
    for account_id in (ACCOUNT_ID, OTHER_ACCOUNT_ID):
        neo4j_session.run(
            """
            MATCH (aa:AWSAccount{id: $account_id})
            MERGE (aa)-[:RESOURCE]->(i:RDSInstance{id: $db})
            SET i.db_instance_identifier = 'database-1', i.region = $region
            MERGE (aa)-[:RESOURCE]->(r:RDSInstance{id: $replica})
            SET r.db_instance_identifier = 'database-1-replica', r.region = $region
            MERGE (aa)-[:RESOURCE]->(c:RDSCluster{id: $cluster})
            SET c.db_cluster_identifier = 'cluster-1', c.region = $region
            MERGE (aa)-[:RESOURCE]->(s:RDSSnapshot{id: $snapshot}) SET s.arn = $snapshot
            MERGE (aa)-[:RESOURCE]->(g:DBSubnetGroup{id: $subnet_group}) SET g.name = 'default'
            """,
            account_id=account_id, region=REGION,
            db=_arn(account_id, 'db', 'database-1'), replica=_arn(account_id, 'db', 'database-1-replica'),
            cluster=_arn(account_id, 'cluster', 'cluster-1'), snapshot=_arn(account_id, 'snapshot', 'snap-1'),
            subnet_group=_arn(account_id, 'subgrp', 'default'),
        )
    # Same identifier in another region of the same account: also not the source.
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (aa)-[:RESOURCE]->(i:RDSInstance{id: $db})
        SET i.db_instance_identifier = 'database-1', i.region = 'us-west-2'
        """,
        account_id=ACCOUNT_ID, db=_arn(ACCOUNT_ID, 'db', 'database-1', 'us-west-2'),
    )


def _targets(neo4j_session, rel, source_id):
    rows = neo4j_session.run(
        f"MATCH (n{{id: $id}})-[:{rel}]->(m) RETURN m.id AS id", id=source_id,
    )
    return {row['id'] for row in rows}


def _sources(neo4j_session, rel, target_id):
    rows = neo4j_session.run(
        f"MATCH (n)-[:{rel}]->(m{{id: $id}}) RETURN n.id AS id", id=target_id,
    )
    return {row['id'] for row in rows}


def test_rds_identifier_links_stay_in_the_account_and_region(neo4j_session):
    _seed(neo4j_session)
    own_db = _arn(ACCOUNT_ID, 'db', 'database-1')
    own_replica = _arn(ACCOUNT_ID, 'db', 'database-1-replica')
    own_snapshot = _arn(ACCOUNT_ID, 'snapshot', 'snap-1')

    rds._attach_snapshots(
        neo4j_session, [{'DBInstanceIdentifier': 'database-1', 'DBSnapshotArn': own_snapshot}],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    rds._attach_read_replicas(
        neo4j_session,
        [{'DBInstanceArn': own_replica, 'ReadReplicaSourceDBInstanceIdentifier': 'database-1'}],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    rds._attach_clusters(
        neo4j_session, [{'DBInstanceArn': own_db, 'DBClusterIdentifier': 'cluster-1'}],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    # Never the other tenant's "database-1"; the same name in another region of this account may be the
    # source of a copied snapshot, so it is kept.
    assert _sources(neo4j_session, 'IS_SNAPSHOT_SOURCE', own_snapshot) == {
        own_db, _arn(ACCOUNT_ID, 'db', 'database-1', 'us-west-2'),
    }
    assert _targets(neo4j_session, 'IS_READ_REPLICA_OF', own_replica) == {own_db}
    assert _targets(neo4j_session, 'IS_CLUSTER_MEMBER_OF', own_db) == {_arn(ACCOUNT_ID, 'cluster', 'cluster-1')}


def test_rds_read_replica_source_given_as_arn_resolves_in_the_account(neo4j_session):
    _seed(neo4j_session)
    own_replica = _arn(ACCOUNT_ID, 'db', 'database-1-replica')
    west_db = _arn(ACCOUNT_ID, 'db', 'database-1', 'us-west-2')

    # Cross-region replicas name their source by ARN.
    rds._attach_read_replicas(
        neo4j_session,
        [
            {'DBInstanceArn': own_replica, 'ReadReplicaSourceDBInstanceIdentifier': west_db},
            {
                'DBInstanceArn': own_replica,
                'ReadReplicaSourceDBInstanceIdentifier': _arn(OTHER_ACCOUNT_ID, 'db', 'database-1'),
            },
        ],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    # The other tenant's ARN is not followed: links never leave the syncing account.
    assert west_db in _targets(neo4j_session, 'IS_READ_REPLICA_OF', own_replica)
    assert _arn(OTHER_ACCOUNT_ID, 'db', 'database-1') not in _targets(neo4j_session, 'IS_READ_REPLICA_OF', own_replica)


def test_rds_cluster_subnet_group_is_the_accounts_own(neo4j_session):
    _seed(neo4j_session)
    cluster = _arn(ACCOUNT_ID, 'cluster', 'cluster-1')

    rds._attach_db_subnet_group(
        neo4j_session, {'DBClusterArn': cluster, 'DBSubnetGroup': 'default', 'region': REGION},
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    assert _targets(neo4j_session, 'ATTACHED_TO', cluster) == {_arn(ACCOUNT_ID, 'subgrp', 'default')}
