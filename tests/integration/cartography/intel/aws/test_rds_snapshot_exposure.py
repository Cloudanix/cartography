import json

import cartography.intel.aws.rds
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777777'
OTHER_ACCOUNT_ID = '888888888888'


def _snapshot_arn(account_id, name):
    return f'arn:aws:rds:us-east-1:{account_id}:snapshot:{name}'


def _load_snapshots(neo4j_session, account_id, snapshots):
    """snapshots: (name, source DB identifier, restore attribute values or None for no attribute result)."""
    cartography.intel.aws.rds.load_rds_snapshots(
        neo4j_session, [
            {
                'DBSnapshotArn': _snapshot_arn(account_id, name),
                'DBSnapshotIdentifier': name,
                'DBInstanceIdentifier': db_id,
                'Engine': 'postgres',
            }
            for name, db_id, _ in snapshots
        ], account_id, TEST_UPDATE_TAG,
    )
    # Shape of describe_db_snapshot_attributes()['DBSnapshotAttributesResult'], plus the ARN sync adds.
    cartography.intel.aws.rds.load_rds_snapshot_attributes(
        neo4j_session, [
            {
                'DBSnapshotArn': _snapshot_arn(account_id, name),
                'DBSnapshotIdentifier': name,
                'DBSnapshotAttributes': [{'AttributeName': 'restore', 'AttributeValues': restore}],
            }
            for name, _, restore in snapshots if restore is not None
        ], TEST_UPDATE_TAG,
    )


def test_rds_snapshot_shared_with_all_is_exposed_whatever_its_source_instance(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-rdss', 'o-rdss', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-rdss-other', 'o-rdss-other', OTHER_ACCOUNT_ID)
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        MERGE (a)-[:RESOURCE]->(:RDSInstance{
            id: 'rdss-private-db-arn', db_instance_identifier: 'rdss-private-db', publicly_accessible: false
        })
        """,
        account_id=ACCOUNT_ID,
    )
    _load_snapshots(
        neo4j_session, ACCOUNT_ID, [
            ('rdss-public-of-private-db', 'rdss-private-db', ['all']),
            ('rdss-shared-with-account', 'rdss-private-db', ['123456789012']),
            ('rdss-not-shared', 'rdss-private-db', []),
            # Source DB deleted: the public snapshot remains restorable by anyone.
            ('rdss-public-orphan', 'rdss-deleted-db', ['all']),
            ('rdss-unshared-since', 'rdss-private-db', []),
        ],
    )
    # Exposed on an earlier sync, unshared since: the job must clear it.
    neo4j_session.run(
        "MATCH (s:RDSSnapshot{db_snapshot_identifier: 'rdss-unshared-since'}) "
        "SET s.exposed_internet = true, s.exposed_internet_type = ['restore_all_attrib']",
    )
    # Another tenant's private snapshot synced afterwards must not change this account's result.
    _load_snapshots(neo4j_session, OTHER_ACCOUNT_ID, [('rdss-other-tenant', 'rdss-other-db', [])])

    run_analysis_job(
        'aws_rds_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-rdss', 'o-rdss', ACCOUNT_ID, TEST_UPDATE_TAG + 1),
    )

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(s:RDSSnapshot{exposed_internet: true})
        RETURN s.db_snapshot_identifier AS name, s.exposed_internet_type AS types, s.publicContext AS context
        """,
        account_id=ACCOUNT_ID,
    )
    exposed = {n['name']: (n['types'], n['context']) for n in nodes}
    assert sorted(exposed) == ['rdss-public-of-private-db', 'rdss-public-orphan']
    types, context = exposed['rdss-public-of-private-db']
    assert types == ['restore_all_attrib']
    context = json.loads(context)[0]['context'][0]
    assert (context['sourceInstanceId'], context['restoreAttribute']) == ('rdss-private-db-arn', ['all'])
    orphan_context = json.loads(exposed['rdss-public-orphan'][1])[0]['context'][0]
    assert (orphan_context['sourceInstanceId'], orphan_context['restoreAttribute']) == (None, ['all'])
