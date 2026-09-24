import re

import botocore.session

from cartography.intel.aws.ec2.snapshots import EBS_SNAPSHOT_FILTERS


def test_ebs_snapshot_filters_request_completed_self_owned():
    assert {
        'Name': 'status',
        'Values': ['completed'],
    } in EBS_SNAPSHOT_FILTERS
    assert {
        'Name': 'owner-alias',
        'Values': ['self'],
    } in EBS_SNAPSHOT_FILTERS


# Regression for https://cloudanix.sentry.io/issues/CDX-CARTOGRAPHY-INVENTORY-6RE: "state" is not a
# DescribeSnapshots filter, so every call failed with InvalidParameterValue.
def test_ebs_snapshot_filters_are_documented_by_ec2():
    docs = botocore.session.get_session().get_service_model('ec2').operation_model(
        'DescribeSnapshots',
    ).input_shape.members['Filters'].documentation
    valid = set(re.findall(r'<li>\s*<p>\s*<code>([a-z:\-]+)</code>', docs))

    assert {f['Name'] for f in EBS_SNAPSHOT_FILTERS} <= valid
