import re
from unittest.mock import MagicMock

import botocore.session

from cartography.intel.aws.ec2 import snapshots
from cartography.intel.aws.ec2.snapshots import EBS_SNAPSHOT_FILTERS


def test_ebs_snapshot_filters_request_completed_snapshots():
    assert EBS_SNAPSHOT_FILTERS == [{'Name': 'status', 'Values': ['completed']}]


# Regression for https://cloudanix.sentry.io/issues/CDX-CARTOGRAPHY-INVENTORY-6RE: "state" is not a
# DescribeSnapshots filter, so every call failed with InvalidParameterValue.
def test_ebs_snapshot_filters_are_documented_by_ec2():
    docs = botocore.session.get_session().get_service_model('ec2').operation_model(
        'DescribeSnapshots',
    ).input_shape.members['Filters'].documentation
    valid = set(re.findall(r'<li>\s*<p>\s*<code>([a-z:\-]+)</code>', docs))

    assert {f['Name'] for f in EBS_SNAPSHOT_FILTERS} <= valid


def test_get_snapshots_lists_own_snapshots_and_marks_public_ones():
    owned = [{'SnapshotId': 'snap-public'}, {'SnapshotId': 'snap-private'}, {'SnapshotId': 'snap-shared'}]

    def paginate(**kwargs):
        # RestorableByUserIds=['all'] returns only the public snapshots (create volume permission for 'all').
        if kwargs.get('RestorableByUserIds') == ['all']:
            return [{'Snapshots': [{'SnapshotId': 'snap-public'}]}]
        return [{'Snapshots': owned[:2]}, {'Snapshots': owned[2:]}]

    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = paginate
    # Real shape; iterating it yields its keys, which is what the previous code did.
    client.describe_snapshot_attribute.return_value = {
        'CreateVolumePermissions': [{'Group': 'all'}], 'SnapshotId': 'snap-public',
    }
    session = MagicMock()
    session.client.return_value = client

    result = snapshots.get_snapshots(session, 'us-east-1')

    calls = [c.kwargs for c in client.get_paginator.return_value.paginate.call_args_list]
    assert {'OwnerIds': ['self'], 'Filters': EBS_SNAPSHOT_FILTERS} in calls
    assert {'OwnerIds': ['self'], 'RestorableByUserIds': ['all']} in calls
    assert {s['SnapshotId']: (s['region'], s['volume_permissions']) for s in result} == {
        'snap-public': ('us-east-1', ['all']),
        'snap-private': ('us-east-1', []),
        'snap-shared': ('us-east-1', []),
    }
    # No per-snapshot attribute calls.
    client.describe_snapshot_attribute.assert_not_called()
