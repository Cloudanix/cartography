import json

import cartography.intel.aws.rds
from cartography.util import run_analysis_job
from cartography.util import run_cleanup_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777771'
OTHER_ACCOUNT_ID = '888888888881'
REGION = 'us-east-1'
CLUSTER = 'rdscs-aurora'


def _snapshot_arn(account_id, name):
    return f'arn:aws:rds:{REGION}:{account_id}:cluster-snapshot:{name}'


def _snapshot(account_id, name, snapshot_type, restore):
    # Shape of describe_db_cluster_snapshots()['DBClusterSnapshots'][n] plus what get_rds_cluster_snapshots adds.
    return {
        'DBClusterSnapshotArn': _snapshot_arn(account_id, name),
        'DBClusterSnapshotIdentifier': name,
        'DBClusterIdentifier': CLUSTER,
        'SnapshotType': snapshot_type,
        'Status': 'available',
        'Engine': 'aurora-postgresql',
        'StorageEncrypted': True,
        'RestoreAttributeValues': restore,
    }


def _load(neo4j_session, account_id, snapshots, update_tag):
    cartography.intel.aws.rds.load_rds_cluster_snapshots(
        neo4j_session, cartography.intel.aws.rds.transform_cluster_snapshots(snapshots, REGION),
        account_id, update_tag,
    )


def test_rds_cluster_snapshot_shared_with_all_is_exposed(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-rdscs', 'o-rdscs', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-rdscs-other', 'o-rdscs-other', OTHER_ACCOUNT_ID)
    # Same cluster identifier in both tenants: a snapshot must link to its own account's cluster only.
    for account_id in (ACCOUNT_ID, OTHER_ACCOUNT_ID):
        neo4j_session.run(
            """
            MATCH (a:AWSAccount{id: $account_id})
            MERGE (a)-[:RESOURCE]->(:RDSCluster{
                id: $arn, db_cluster_identifier: $cluster, region: $region
            })
            """,
            account_id=account_id, arn=f'arn:aws:rds:{REGION}:{account_id}:cluster:{CLUSTER}',
            cluster=CLUSTER, region=REGION,
        )

    # Deleted since: the next sync's cleanup removes it.
    _load(neo4j_session, ACCOUNT_ID, [_snapshot(ACCOUNT_ID, 'rdscs-deleted', 'manual', ['all'])], TEST_UPDATE_TAG)
    _load(
        neo4j_session, ACCOUNT_ID, [
            _snapshot(ACCOUNT_ID, 'rdscs-public', 'manual', ['all']),
            _snapshot(ACCOUNT_ID, 'rdscs-shared-with-account', 'manual', ['123456789012']),
            _snapshot(ACCOUNT_ID, 'rdscs-unshared-since', 'manual', []),
            _snapshot(ACCOUNT_ID, 'rds:rdscs-automated', 'automated', None),
            _snapshot(ACCOUNT_ID, 'rdscs-denied', 'manual', None),
        ], TEST_UPDATE_TAG + 1,
    )
    _load(
        neo4j_session, OTHER_ACCOUNT_ID, [_snapshot(OTHER_ACCOUNT_ID, 'rdscs-other-public', 'manual', ['all'])],
        TEST_UPDATE_TAG + 1,
    )
    # Exposed on an earlier sync, unshared since: the job must clear it.
    neo4j_session.run(
        "MATCH (s:RDSClusterSnapshot{db_cluster_snapshot_identifier: 'rdscs-unshared-since'}) "
        "SET s.exposed_internet = true, s.exposed_internet_type = ['restore_all_attrib']",
    )

    parameters = exposure_job_parameters('ws-rdscs', 'o-rdscs', ACCOUNT_ID, TEST_UPDATE_TAG + 1)
    run_cleanup_job('aws_import_rds_cluster_snapshots_cleanup.json', neo4j_session, parameters)
    run_analysis_job('aws_rds_asset_exposure.json', neo4j_session, parameters)

    rows = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(s:RDSClusterSnapshot)
        OPTIONAL MATCH (c:RDSCluster)-[:IS_SNAPSHOT_SOURCE]->(s)
        RETURN s.db_cluster_snapshot_identifier AS name, s.exposed_internet AS exposed,
               s.exposed_internet_type AS types, s.publicContext AS context, collect(c.id) AS clusters
        """,
        account_id=ACCOUNT_ID,
    )
    snapshots = {r['name']: r for r in rows}
    assert sorted(snapshots) == [
        'rds:rdscs-automated', 'rdscs-denied', 'rdscs-public', 'rdscs-shared-with-account', 'rdscs-unshared-since',
    ]
    assert {name for name, r in snapshots.items() if r['exposed']} == {'rdscs-public'}
    public = snapshots['rdscs-public']
    assert public['types'] == ['restore_all_attrib']
    assert public['clusters'] == [f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:cluster:{CLUSTER}']
    context = json.loads(public['context'])[0]
    assert context['resourceType'] == 'aws-database-rds-cluster-snapshot'
    assert (context['context'][0]['sourceClusterId'], context['context'][0]['restoreAttribute']) == (
        f'arn:aws:rds:{REGION}:{ACCOUNT_ID}:cluster:{CLUSTER}', ['all'],
    )
    assert snapshots['rdscs-unshared-since']['context'] is None
    # The other tenant's snapshot is left to its own account's job run.
    other = neo4j_session.run(
        "MATCH (s:RDSClusterSnapshot{db_cluster_snapshot_identifier: 'rdscs-other-public'}) "
        "RETURN s.exposed_internet AS exposed",
    ).single()
    assert other['exposed'] is None
