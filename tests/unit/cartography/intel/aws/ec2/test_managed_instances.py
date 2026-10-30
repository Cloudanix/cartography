"""
Unit tests for AWS EC2 managed instances (instances a service provider such as EKS Auto Mode or
ECS Managed Instances runs in the customer's account). AWS hides them from DescribeInstances by
default, so the list call must opt in, and the Operator block must reach the graph.
https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/amazon-ec2-managed-instances.html
"""
from unittest.mock import MagicMock

from cartography.intel.aws.ec2.instances import get_ec2_instances


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
