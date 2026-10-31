import cartography.intel.aws.rds
from cartography.util import run_cleanup_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777777'
OTHER_ACCOUNT_ID = '888888888888'
# The identifier is only unique within an account and region; both accounts use the same one.
SNAPSHOT_NAME = 'rdsa-nightly'


def _snapshot_arn(account_id):
    return f'arn:aws:rds:us-east-1:{account_id}:snapshot:{SNAPSHOT_NAME}'


def _load_snapshot(neo4j_session, account_id, attributes, update_tag):
    cartography.intel.aws.rds.load_rds_snapshots(
        neo4j_session, [
            {
                'DBSnapshotArn': _snapshot_arn(account_id),
                'DBSnapshotIdentifier': SNAPSHOT_NAME,
                'DBInstanceIdentifier': 'rdsa-db',
            },
        ], account_id, update_tag,
    )
    # Shape of describe_db_snapshot_attributes()['DBSnapshotAttributesResult'], plus the ARN sync adds.
    cartography.intel.aws.rds.load_rds_snapshot_attributes(
        neo4j_session, [
            {
                'DBSnapshotArn': _snapshot_arn(account_id),
                'DBSnapshotIdentifier': SNAPSHOT_NAME,
                'DBSnapshotAttributes': [
                    {'AttributeName': name, 'AttributeValues': values} for name, values in attributes.items()
                ],
            },
        ], update_tag,
    )


def _attributes_of(neo4j_session, account_id):
    rows = neo4j_session.run(
        """
        MATCH (s:RDSSnapshot{id: $arn})-[:HAS_ATTRIBUTE]->(a:RDSSnapshotAttribute)
        OPTIONAL MATCH (a)<-[:HAS_ATTRIBUTE]-(other:RDSSnapshot)
        RETURN a.id AS id, a.name AS name, a.values AS values, count(other) AS snapshots
        """,
        arn=_snapshot_arn(account_id),
    )
    return {r['name']: (r['id'], r['values'], r['snapshots']) for r in rows}


def test_rds_snapshot_attributes_belong_to_their_own_snapshot(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-rdsa', 'o-rdsa', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-rdsa-other', 'o-rdsa-other', OTHER_ACCOUNT_ID)
    # Left over by the old loader: one node per attribute name, shared by every snapshot in the graph.
    neo4j_session.run(
        """
        MERGE (legacy:RDSSnapshotAttribute{name: 'restore'}) SET legacy.values = ['all']
        WITH legacy MATCH (s:RDSSnapshot) MERGE (s)-[:HAS_ATTRIBUTE]->(legacy)
        """,
    )

    # The first sync shares the snapshot with everyone; the second unshares it and drops a 'backup' attribute.
    _load_snapshot(neo4j_session, ACCOUNT_ID, {'restore': ['all'], 'backup': ['all']}, TEST_UPDATE_TAG)
    _load_snapshot(neo4j_session, ACCOUNT_ID, {'restore': []}, TEST_UPDATE_TAG + 1)
    # Another tenant's same-named snapshot, written last, keeps its own values.
    _load_snapshot(neo4j_session, OTHER_ACCOUNT_ID, {'restore': ['123456789012']}, TEST_UPDATE_TAG + 1)

    run_cleanup_job(
        'aws_import_rds_snapshots_cleanup.json', neo4j_session,
        exposure_job_parameters('ws-rdsa', 'o-rdsa', ACCOUNT_ID, TEST_UPDATE_TAG + 1),
    )

    assert _attributes_of(neo4j_session, ACCOUNT_ID) == {
        'restore': (f'{_snapshot_arn(ACCOUNT_ID)}/restore', [], 1),
    }
    assert _attributes_of(neo4j_session, OTHER_ACCOUNT_ID) == {
        'restore': (f'{_snapshot_arn(OTHER_ACCOUNT_ID)}/restore', ['123456789012'], 1),
    }
    legacy = neo4j_session.run("MATCH (a:RDSSnapshotAttribute) WHERE a.id IS NULL RETURN count(a) AS n").single()
    assert legacy['n'] == 0
