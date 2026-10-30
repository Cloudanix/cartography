"""
Unit tests for AWS EC2 managed instances (instances a service provider such as EKS Auto Mode or
ECS Managed Instances runs in the customer's account). AWS hides them from DescribeInstances by
default, so the list call must opt in, and the Operator block must reach the graph.
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-managed-instances.html
"""
from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.aws.ec2.instances import get_ec2_instances
from cartography.intel.aws.ec2.instances import transform_ec2_instances
from cartography.models.aws.ec2.instances import EC2InstanceNodeProperties


def _transform_one(instance_overrides):
    """Run transform_ec2_instances over one minimal instance and return its transformed dict."""
    instance = {
        "InstanceId": "i-test01",
        "ImageId": "ami-12345",
        "InstanceType": "t3.micro",
        "State": {"Name": "running"},
        "LaunchTime": None,
        "NetworkInterfaces": [],
        "BlockDeviceMappings": [],
        "Tags": [],
    }
    instance.update(instance_overrides)
    reservation = {"ReservationId": "r-test01", "OwnerId": "123456789012", "Instances": [instance]}
    with patch(
        "cartography.intel.aws.ec2.instances.get_roles_from_instance_profile",
        return_value=[],
    ):
        ec2_data = transform_ec2_instances(MagicMock(), [reservation], "us-east-1", "123456789012")
    return ec2_data.instance_list[0]


def _session_with_pages(pages):
    """Build a boto3 session mock whose describe_instances paginator yields the given pages."""
    session = MagicMock()
    client = session.client.return_value
    client.get_paginator.return_value.paginate.return_value = pages
    client.describe_images.return_value = {"Images": []}
    return session, client


class TestGetEc2InstancesIncludesManaged:
    def test_paginate_requests_managed_resources(self):
        session, client = _session_with_pages([{"Reservations": []}])

        get_ec2_instances(session, "us-east-1")

        client.get_paginator.assert_called_once_with("describe_instances")
        client.get_paginator.return_value.paginate.assert_called_once_with(IncludeManagedResources=True)

    def test_all_pages_are_collected(self):
        pages = [
            {"Reservations": [{"ReservationId": "r-1", "Instances": [{"InstanceId": "i-1"}]}]},
            {"Reservations": [{"ReservationId": "r-2", "Instances": [{"InstanceId": "i-2"}]}]},
        ]
        session, _client = _session_with_pages(pages)

        reservations = get_ec2_instances(session, "us-east-1")

        assert [r["ReservationId"] for r in reservations] == ["r-1", "r-2"]
        assert all(r["region"] == "us-east-1" for r in reservations)


class TestInstanceOperatorTransform:
    def test_managed_instance_carries_operator(self):
        instance = _transform_one(
            {"Operator": {"Managed": True, "Principal": "eks.amazonaws.com", "HiddenByDefault": True}},
        )

        assert instance["OperatorManaged"] is True
        assert instance["OperatorPrincipal"] == "eks.amazonaws.com"

    def test_unmanaged_instance_has_no_operator_values(self):
        """Absent Operator means not managed; values stay None so the graph property is never set."""
        instance = _transform_one({})

        assert instance["OperatorManaged"] is None
        assert instance["OperatorPrincipal"] is None

    def test_operator_fields_in_model(self):
        props = EC2InstanceNodeProperties()

        assert props.operatormanaged.name == "OperatorManaged"
        assert props.operatorprincipal.name == "OperatorPrincipal"
