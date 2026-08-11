from cartography.intel.aws.ec2.snapshots import EBS_SNAPSHOT_FILTERS


def test_ebs_snapshot_filters_request_completed_self_owned():
    assert {
        'Name': 'state',
        'Values': ['completed'],
    } in EBS_SNAPSHOT_FILTERS
    assert {
        'Name': 'owner-alias',
        'Values': ['self'],
    } in EBS_SNAPSHOT_FILTERS
