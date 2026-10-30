"""
Unit tests for EBS volumes of AWS EC2 managed instances. AWS hides managed resources from
DescribeVolumes by default, so the list call must opt in, and the Operator block must reach the graph.
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-managed-instances.html
"""
from unittest.mock import MagicMock

from cartography.intel.aws.ec2.volumes import get_volumes


def _session_with_pages(pages):
    """Build a boto3 session mock whose describe_volumes paginator yields the given pages."""
    session = MagicMock()
    client = session.client.return_value
    client.get_paginator.return_value.paginate.return_value = pages
    return session, client


class TestGetVolumesIncludesManaged:
    def test_paginate_requests_managed_resources(self):
        session, client = _session_with_pages([{"Volumes": []}])

        get_volumes(session, "us-east-1")

        client.get_paginator.assert_called_once_with("describe_volumes")
        client.get_paginator.return_value.paginate.assert_called_once_with(IncludeManagedResources=True)

    def test_all_pages_are_collected(self):
        pages = [{"Volumes": [{"VolumeId": "vol-1"}]}, {"Volumes": [{"VolumeId": "vol-2"}]}]
        session, _client = _session_with_pages(pages)

        volumes = get_volumes(session, "us-east-1")

        assert [v["VolumeId"] for v in volumes] == ["vol-1", "vol-2"]
