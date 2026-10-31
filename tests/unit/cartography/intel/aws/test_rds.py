from unittest.mock import MagicMock

from cartography.intel.aws import rds
from cartography.intel.aws.rds import filter_active_rds_reserved_db_instances
from cartography.intel.aws.rds import filter_available_rds_snapshots


def test_filter_active_rds_reserved_db_instances_keeps_active_only():
    instances = [
        {'ReservedDBInstanceId': 'ri-active', 'State': 'active'},
        {'ReservedDBInstanceId': 'ri-retired', 'State': 'retired'},
        {'ReservedDBInstanceId': 'ri-payment-failed', 'State': 'payment-failed'},
        {'ReservedDBInstanceId': 'ri-payment-pending', 'State': 'payment-pending'},
        {'ReservedDBInstanceId': 'ri-missing-state'},
    ]

    filtered = filter_active_rds_reserved_db_instances(instances)

    assert [i['ReservedDBInstanceId'] for i in filtered] == ['ri-active']


def test_filter_active_rds_reserved_db_instances_empty():
    assert filter_active_rds_reserved_db_instances([]) == []


def test_filter_available_rds_snapshots_keeps_available_only():
    snapshots = [
        {'DBSnapshotIdentifier': 'snap-ok', 'Status': 'available'},
        {'DBSnapshotIdentifier': 'snap-creating', 'Status': 'creating'},
        {'DBSnapshotIdentifier': 'snap-error', 'Status': 'error'},
        {'DBSnapshotIdentifier': 'snap-missing'},
    ]
    filtered = filter_available_rds_snapshots(snapshots)
    assert [s['DBSnapshotIdentifier'] for s in filtered] == ['snap-ok']


def test_filter_available_rds_snapshots_empty():
    assert filter_available_rds_snapshots([]) == []


SNAPSHOT_ARN_PREFIX = 'arn:aws:rds:us-east-1:111111111111:snapshot:'


def test_sync_rds_snapshots_keys_attribute_results_by_snapshot_arn(mocker):
    snapshots = [
        {'DBSnapshotIdentifier': 'snap-public', 'DBSnapshotArn': SNAPSHOT_ARN_PREFIX + 'snap-public'},
        {'DBSnapshotIdentifier': 'snap-denied', 'DBSnapshotArn': SNAPSHOT_ARN_PREFIX + 'snap-denied'},
    ]
    attributes = {
        'snap-public': {
            'DBSnapshotIdentifier': 'snap-public',
            'DBSnapshotAttributes': [{'AttributeName': 'restore', 'AttributeValues': ['all']}],
        },
        # get_rds_snapshot_attributes returns {} when the call is denied.
        'snap-denied': {},
    }
    mocker.patch.object(rds, 'get_rds_snapshots', return_value=snapshots)
    mocker.patch.object(
        rds, 'get_rds_snapshot_attributes', side_effect=lambda _, snapshot_id, __: attributes[snapshot_id],
    )
    mocker.patch.object(rds, 'load_rds_snapshots')
    mocker.patch.object(rds, 'cleanup_rds_snapshots')
    load_attributes = mocker.patch.object(rds, 'load_rds_snapshot_attributes')

    rds.sync_rds_snapshots(MagicMock(), MagicMock(), ['us-east-1'], '111111111111', 42, {})

    load_attributes.assert_called_once()
    assert load_attributes.call_args.args[1] == [{
        'DBSnapshotIdentifier': 'snap-public',
        'DBSnapshotAttributes': [{'AttributeName': 'restore', 'AttributeValues': ['all']}],
        'DBSnapshotArn': SNAPSHOT_ARN_PREFIX + 'snap-public',
    }]
