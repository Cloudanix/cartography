"""
Unit tests for the batched Redshift loaders (perf plan Phase 3.5).
"""
from unittest.mock import MagicMock

from cartography.intel.aws import redshift

TEST_UPDATE_TAG = 123456789
TEST_ACCOUNT_ID = "1234"

CLUSTER = {
    "arn": "arn:aws:redshift:us-east-1:1234:cluster:c1",
    "AvailabilityZone": "us-east-1a",
    "ClusterIdentifier": "c1",
    "ClusterStatus": "available",
    "Endpoint": {"Address": "c1.redshift.amazonaws.com", "Port": 5439},
    "VpcId": "vpc-1",
    "region": "us-east-1",
    "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-1", "GroupId": "sg-1", "region": "us-east-1"}],
    "IamRoles": [{"IamRoleArn": "arn:aws:iam::1234:role/redshift"}],
    "VpcEndpoints": [
        {"NetworkInterfaces": [{"NetworkInterfaceId": "eni-1", "SubnetId": "subnet-1"}]},
    ],
}


class TestLoadRedshiftClusterData:
    def test_batched_writes(self):
        session = MagicMock()

        redshift.load_redshift_cluster_data(session, [CLUSTER, CLUSTER], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        # clusters + SGs + IAM roles + VPCs + NICs + subnets = 6 writes total
        assert session.execute_write.call_count == 6
        cluster_call, sg_call, role_call, vpc_call, nic_call, subnet_call = session.execute_write.call_args_list
        assert len(cluster_call.kwargs["DictList"]) == 2
        assert cluster_call.kwargs["DictList"][0]["endpoint_address"] == "c1.redshift.amazonaws.com"
        assert sg_call.kwargs["DictList"][0]["group_id"] == "sg-1"
        assert role_call.kwargs["DictList"][0]["role_arn"] == "arn:aws:iam::1234:role/redshift"
        assert vpc_call.kwargs["DictList"][0]["vpc_id"] == "vpc-1"
        assert nic_call.kwargs["DictList"][0]["network_interface_id"] == "eni-1"
        assert subnet_call.kwargs["DictList"][0]["subnet_id"] == "subnet-1"
        assert all("UNWIND $DictList" in c.args[1] for c in session.execute_write.call_args_list)

    def test_cluster_without_optional_attachments(self):
        session = MagicMock()
        bare = {**CLUSTER, "VpcSecurityGroups": [], "IamRoles": [], "VpcId": None, "VpcEndpoints": [], "Endpoint": None}

        redshift.load_redshift_cluster_data(session, [bare], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1  # only the cluster batch
        assert session.execute_write.call_args.kwargs["DictList"][0]["endpoint_address"] == ""

    def test_empty_data_writes_nothing(self):
        session = MagicMock()
        redshift.load_redshift_cluster_data(session, [], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()
