from cartography.intel.aws.ec2.snapshots import filter_completed_ebs_snapshots


def test_filter_completed_ebs_snapshots_keeps_completed_only():
    snapshots = [
        {'SnapshotId': 'snap-done', 'State': 'completed'},
        {'SnapshotId': 'snap-pending', 'State': 'pending'},
        {'SnapshotId': 'snap-error', 'State': 'error'},
        {'SnapshotId': 'snap-missing'},
    ]
    filtered = filter_completed_ebs_snapshots(snapshots)
    assert [s['SnapshotId'] for s in filtered] == ['snap-done']


def test_filter_completed_ebs_snapshots_empty():
    assert filter_completed_ebs_snapshots([]) == []
