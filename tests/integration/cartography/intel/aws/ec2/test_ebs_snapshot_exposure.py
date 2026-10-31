import json

import cartography.intel.aws.ec2.snapshots
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777772'
OTHER_ACCOUNT_ID = '888888888882'


def _load(neo4j_session, account_id, snapshots):
    # Shape of describe_snapshots()['Snapshots'][n] plus what get_snapshots adds.
    cartography.intel.aws.ec2.snapshots.load_snapshots(
        neo4j_session, [
            {
                'SnapshotId': snapshot_id, 'StartTime': '2026-10-01', 'VolumeId': 'vol-ebsx', 'VolumeSize': 8,
                'Encrypted': False, 'region': 'us-east-1', 'volume_permissions': permissions,
            }
            for snapshot_id, permissions in snapshots
        ], account_id, TEST_UPDATE_TAG,
    )


def test_ebs_snapshot_public_when_create_volume_permission_is_all(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-ebsx', 'o-ebsx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-ebsx-other', 'o-ebsx-other', OTHER_ACCOUNT_ID)
    _load(neo4j_session, ACCOUNT_ID, [('snap-ebsx-public', ['all']), ('snap-ebsx-private', [])])
    _load(neo4j_session, ACCOUNT_ID, [('snap-ebsx-unshared-since', [])])
    _load(neo4j_session, OTHER_ACCOUNT_ID, [('snap-ebsx-other-public', ['all'])])
    neo4j_session.run(
        "MATCH (s:EBSSnapshot{id: 'snap-ebsx-unshared-since'}) "
        "SET s.exposed_internet = true, s.exposed_internet_type = ['ebs_volume_permissions_group']",
    )

    run_analysis_job(
        'aws_ebs_snapshot_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-ebsx', 'o-ebsx', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (s:EBSSnapshot) WHERE s.id STARTS WITH 'snap-ebsx' "
        "RETURN s.id AS id, s.exposed_internet AS exposed, s.exposed_internet_type AS types, "
        "s.publicContext AS context",
    )
    snapshots = {r['id']: r for r in rows}
    assert {i for i, r in snapshots.items() if r['exposed']} == {'snap-ebsx-public'}
    assert snapshots['snap-ebsx-public']['types'] == ['ebs_volume_permissions_group']
    context = json.loads(snapshots['snap-ebsx-public']['context'])[0]['context'][0]
    assert context['volumePermissions'] == ['all']
    assert snapshots['snap-ebsx-unshared-since']['context'] is None
