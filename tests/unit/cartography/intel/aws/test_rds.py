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
