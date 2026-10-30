"""
Unit tests for EBS volumes of AWS EC2 managed instances. AWS hides managed resources from
DescribeVolumes by default, so the list call must opt in, and the Operator block must reach the graph.
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-managed-instances.html
"""
from unittest.mock import MagicMock

from cartography.intel.aws.ec2.volumes import get_volumes
from cartography.intel.aws.ec2.volumes import transform_volumes
from cartography.models.aws.ec2.volumes import EBSVolumeNodeProperties


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


def _transform_one(volume_overrides):
    """Run transform_volumes over one minimal unattached volume and return its transformed dict."""
    volume = {"VolumeId": "vol-test01", "AvailabilityZone": "us-east-1a", "State": "available", "Attachments": []}
    volume.update(volume_overrides)
    return transform_volumes([volume], "us-east-1", "123456789012")[0]


class TestVolumeOperatorTransform:
    def test_managed_volume_carries_operator(self):
        volume = _transform_one({"Operator": {"Managed": True, "Principal": "eks.amazonaws.com"}})

        assert volume["OperatorManaged"] is True
        assert volume["OperatorPrincipal"] == "eks.amazonaws.com"

    def test_unmanaged_volume_has_no_operator_values(self):
        """Absent Operator means not managed; values stay None so the graph property is never set."""
        volume = _transform_one({})

        assert volume["OperatorManaged"] is None
        assert volume["OperatorPrincipal"] is None

    def test_operator_fields_in_model(self):
        props = EBSVolumeNodeProperties()

        assert props.operatormanaged.name == "OperatorManaged"
        assert props.operatorprincipal.name == "OperatorPrincipal"
