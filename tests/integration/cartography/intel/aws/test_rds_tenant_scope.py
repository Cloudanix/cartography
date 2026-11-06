from cartography.intel.aws import rds
from cartography.util import run_cleanup_job
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777801'
OTHER_ACCOUNT_ID = '888888888801'
SIBLING_ACCOUNT_ID = '777777777802'  # same workspace as ACCOUNT_ID
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


def test_rds_cleanup_removes_links_the_sync_no_longer_writes(neo4j_session):
    _seed(neo4j_session)
    own_snapshot = _arn(ACCOUNT_ID, 'snapshot', 'snap-1')
    own_cluster = _arn(ACCOUNT_ID, 'cluster', 'cluster-1')
    other_db = _arn(OTHER_ACCOUNT_ID, 'db', 'database-1')
    other_snapshot = _arn(OTHER_ACCOUNT_ID, 'snapshot', 'snap-1')
    stale, fresh = TEST_UPDATE_TAG - 1, TEST_UPDATE_TAG
    # Edges the old name-only matching left behind, plus a link this sync just wrote and another tenant's own link.
    neo4j_session.run(
        """
        MATCH (od:RDSInstance{id: $other_db}), (s:RDSSnapshot{id: $own_snapshot}),
              (os:RDSSnapshot{id: $other_snapshot}),
              (c:RDSCluster{id: $own_cluster}), (og:DBSubnetGroup{id: $other_group}), (g:DBSubnetGroup{id: $own_group}),
              (d:RDSInstance{id: $own_db})
        MERGE (od)-[r1:IS_SNAPSHOT_SOURCE]->(s) SET r1.lastupdated = $stale
        MERGE (d)-[r2:IS_SNAPSHOT_SOURCE]->(s) SET r2.lastupdated = $fresh
        MERGE (od)-[r3:IS_SNAPSHOT_SOURCE]->(os) SET r3.lastupdated = $stale
        MERGE (c)-[r4:ATTACHED_TO]->(og) SET r4.lastupdated = $stale
        MERGE (c)-[r5:ATTACHED_TO]->(g) SET r5.lastupdated = $fresh
        """,
        other_db=other_db, own_snapshot=own_snapshot, other_snapshot=other_snapshot, own_cluster=own_cluster,
        own_db=_arn(ACCOUNT_ID, 'db', 'database-1'),
        other_group=_arn(OTHER_ACCOUNT_ID, 'subgrp', 'default'), own_group=_arn(ACCOUNT_ID, 'subgrp', 'default'),
        stale=stale, fresh=fresh,
    )
    params = {
        'UPDATE_TAG': fresh, 'AWS_ID': ACCOUNT_ID, 'ORGANIZATION_ID': 'o-rds', 'WORKSPACE_ID': 'ws-rds',
        'LIMIT_SIZE': 100,
    }

    run_cleanup_job('aws_import_rds_snapshots_cleanup.json', neo4j_session, params)
    run_cleanup_job('aws_import_rds_clusters_cleanup.json', neo4j_session, params)

    sources = _sources(neo4j_session, 'IS_SNAPSHOT_SOURCE', own_snapshot)
    assert other_db not in sources
    assert _arn(ACCOUNT_ID, 'db', 'database-1') in sources
    assert _targets(neo4j_session, 'ATTACHED_TO', own_cluster) == {_arn(ACCOUNT_ID, 'subgrp', 'default')}
    # The other tenant's own snapshot link belongs to its sync and cleanup, not this one.
    assert _sources(neo4j_session, 'IS_SNAPSHOT_SOURCE', other_snapshot) == {other_db}


def _seed_link_targets(neo4j_session):
    # SIBLING is another account of this customer's workspace; OTHER belongs to another customer.
    create_test_org_account(neo4j_session, 'ws-rds', 'o-rds', SIBLING_ACCOUNT_ID)
    for account_id in (ACCOUNT_ID, SIBLING_ACCOUNT_ID, OTHER_ACCOUNT_ID):
        neo4j_session.run(
            """
            MATCH (aa:AWSAccount{id: $account_id})
            MERGE (aa)-[:RESOURCE]->(:EC2SecurityGroup{id: 'sg-' + $account_id})
            MERGE (aa)-[:RESOURCE]->(:RDSSecurityGroup{id: $dbsg})
            """,
            account_id=account_id, dbsg=_arn(account_id, 'secgrp', 'legacy'),
        )


def test_rds_links_from_another_tenants_nodes_are_never_written(neo4j_session):
    _seed(neo4j_session)
    _seed_link_targets(neo4j_session)
    own_cluster, other_cluster = (_arn(a, 'cluster', 'cluster-1') for a in (ACCOUNT_ID, OTHER_ACCOUNT_ID))
    own_db, other_db = (_arn(a, 'db', 'database-1') for a in (ACCOUNT_ID, OTHER_ACCOUNT_ID))
    own_snapshot, other_snapshot = (_arn(a, 'snapshot', 'snap-1') for a in (ACCOUNT_ID, OTHER_ACCOUNT_ID))
    own_dbsg, other_dbsg = (_arn(a, 'secgrp', 'legacy') for a in (ACCOUNT_ID, OTHER_ACCOUNT_ID))
    clusters = [
        {
            'DBClusterArn': arn, 'DBSubnetGroup': 'cluster-sng', 'region': REGION,
            'AssociatedRoles': [{'RoleArn': 'arn:aws:iam::777777777801:role/rds-s3'}],
            'VpcSecurityGroups': [{'VpcSecurityGroupId': 'sg-cluster'}],
        }
        for arn in (own_cluster, other_cluster)
    ]
    instances = [
        {
            'DBInstanceArn': arn, 'region': REGION, 'VpcSecurityGroups': [{'VpcSecurityGroupId': 'sg-instance'}],
            'DBSubnetGroup': {
                'DBSubnetGroupName': f'sng-{n}', 'Subnets': [{'SubnetIdentifier': f'subnet-rds-{n}'}],
            },
        }
        for n, arn in enumerate((own_db, other_db))
    ]
    attributes = [
        {'DBSnapshotArn': arn, 'DBSnapshotAttributes': [{'AttributeName': 'restore', 'AttributeValues': ['all']}]}
        for arn in (own_snapshot, other_snapshot)
    ]

    rds.attach_db_security_groups_to_ec2_security_groups(
        neo4j_session,
        [
            {
                'DBSecurityGroupArn': own_dbsg,
                'EC2SecurityGroups': [
                    {'EC2SecurityGroupId': f'sg-{a}'} for a in (ACCOUNT_ID, SIBLING_ACCOUNT_ID, OTHER_ACCOUNT_ID)
                ],
            },
            {'DBSecurityGroupArn': other_dbsg, 'EC2SecurityGroups': [{'EC2SecurityGroupId': f'sg-{ACCOUNT_ID}'}]},
        ],
        ACCOUNT_ID, 'ws-rds', TEST_UPDATE_TAG,
    )
    rds._attach_associate_roles(neo4j_session, clusters, ACCOUNT_ID, TEST_UPDATE_TAG)
    for cluster in clusters:
        rds._attach_db_subnet_group(neo4j_session, cluster, ACCOUNT_ID, TEST_UPDATE_TAG)
        rds._attach_ec2_security_groups_cluster(neo4j_session, cluster, ACCOUNT_ID, TEST_UPDATE_TAG)
    rds._attach_ec2_security_groups(neo4j_session, instances, ACCOUNT_ID, TEST_UPDATE_TAG)
    rds._attach_ec2_subnet_groups(neo4j_session, instances, ACCOUNT_ID, TEST_UPDATE_TAG)
    rds.load_rds_snapshot_attributes(neo4j_session, attributes, ACCOUNT_ID, TEST_UPDATE_TAG)

    # A sibling account's EC2 group is linked; another customer's is not, nor is their DB security group.
    assert _targets(neo4j_session, 'USING', own_dbsg) == {f'sg-{ACCOUNT_ID}', f'sg-{SIBLING_ACCOUNT_ID}'}
    assert _targets(neo4j_session, 'USING', other_dbsg) == set()
    roles = neo4j_session.run(
        "MATCH (c:RDSCluster)-[:RDS_ASSUMEROLE_ALLOW]->(:AWSPrincipal) RETURN collect(c.id) AS ids",
    ).single()['ids']
    assert roles == [own_cluster]
    assert _targets(neo4j_session, 'MEMBER_OF_EC2_SECURITY_GROUP', own_cluster) == {'sg-cluster'}
    assert _targets(neo4j_session, 'MEMBER_OF_EC2_SECURITY_GROUP', other_cluster) == set()
    assert _arn(ACCOUNT_ID, 'subgrp', 'cluster-sng') in _targets(neo4j_session, 'ATTACHED_TO', own_cluster)
    assert _targets(neo4j_session, 'ATTACHED_TO', other_cluster) == set()
    assert _targets(neo4j_session, 'MEMBER_OF_EC2_SECURITY_GROUP', own_db) == {'sg-instance'}
    assert _targets(neo4j_session, 'MEMBER_OF_EC2_SECURITY_GROUP', other_db) == set()
    assert _targets(neo4j_session, 'MEMBER_OF_DB_SUBNET_GROUP', other_db) == set()
    assert _targets(neo4j_session, 'MEMBER_OF_DB_SUBNET_GROUP', own_db) == {_arn(ACCOUNT_ID, 'subgrp', 'sng-0')}
    subnets = neo4j_session.run(
        "MATCH (:DBSubnetGroup)-[:CONNECTED_TO]->(s:EC2Subnet) RETURN collect(s.subnetid) AS ids",
    ).single()['ids']
    assert subnets == ['subnet-rds-0']
    snapshots = neo4j_session.run(
        """
        MATCH (s:RDSSnapshot) WHERE s.id IN [$own, $other]
        RETURN s.id AS id, s.restore_attribute_values AS restore, size([(s)-[:HAS_ATTRIBUTE]->() | 1]) AS attrs
        """,
        own=own_snapshot, other=other_snapshot,
    )
    assert {(r['id'], tuple(r['restore'] or []), r['attrs']) for r in snapshots} == {
        (own_snapshot, ('all',), 1), (other_snapshot, (), 0),
    }


def test_rds_cluster_links_are_written_on_the_first_sync(neo4j_session):
    # The links reach the cluster from the account, so they must run after the cluster loads.
    account_id = '777777777803'
    cluster_arn = _arn(account_id, 'cluster', 'fresh-cluster')
    create_test_org_account(neo4j_session, 'ws-rds-fresh', 'o-rds-fresh', account_id)

    rds.load_rds_clusters(
        neo4j_session,
        [{
            'DBClusterArn': cluster_arn, 'DBClusterIdentifier': 'fresh-cluster', 'region': REGION,
            'DBSubnetGroup': 'default', 'AssociatedRoles': [{'RoleArn': f'arn:aws:iam::{account_id}:role/r'}],
            'VpcSecurityGroups': [{'VpcSecurityGroupId': 'sg-fresh'}],
        }],
        account_id, TEST_UPDATE_TAG,
    )

    links = neo4j_session.run(
        "MATCH (:RDSCluster{id: $id})-[r]->() RETURN collect(type(r)) AS types", id=cluster_arn,
    ).single()['types']
    assert sorted(links) == ['ATTACHED_TO', 'MEMBER_OF_EC2_SECURITY_GROUP', 'RDS_ASSUMEROLE_ALLOW']
