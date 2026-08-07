"""
Unit tests for uniform neo4j interactions in the aws/ec2 intel modules
(perf plan Phase 3 items 5+6).
"""
from datetime import datetime
from unittest.mock import MagicMock

from cartography.intel.aws.ec2 import auto_scaling_groups
from cartography.intel.aws.ec2 import elastic_ip_addresses
from cartography.intel.aws.ec2 import images
from cartography.intel.aws.ec2 import instances
from cartography.intel.aws.ec2 import internet_gateways
from cartography.intel.aws.ec2 import key_pairs
from cartography.intel.aws.ec2 import launch_templates
from cartography.intel.aws.ec2 import reserved_instances
from cartography.intel.aws.ec2 import snapshots
from cartography.intel.aws.ec2 import subnets
from cartography.intel.aws.ec2 import tgw
from cartography.intel.aws.ec2 import volumes
from cartography.intel.aws.ec2 import vpc
from cartography.intel.aws.ec2 import vpc_peerings

TEST_UPDATE_TAG = 123456789
TEST_ACCOUNT_ID = "1234"
TEST_REGION = "us-east-1"
NOW = datetime(2024, 1, 1)


def assert_batched(call, rows):
    assert "UNWIND $DictList" in call.args[1]
    assert call.kwargs["DictList"] == rows


class TestBatchedLoaders:
    def test_launch_configurations(self):
        session = MagicMock()
        data = [{
            "LaunchConfigurationARN": "arn:aws:autoscaling:us-east-1:1234:launchConfiguration:lc-1",
            "CreatedTime": NOW,
        }]

        auto_scaling_groups.load_launch_configurations(
            session, data, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
        )

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_elastic_ip_addresses(self):
        session = MagicMock()
        data = [{"PublicIp": "1.2.3.4", "AllocationId": "eipalloc-1", "region": TEST_REGION}]

        elastic_ip_addresses.load_elastic_ip_addresses(session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_images(self):
        session = MagicMock()
        data = [{"ImageId": "ami-1", "region": TEST_REGION}]

        images.load_images(session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_internet_gateways(self):
        session = MagicMock()
        data = [{"InternetGatewayId": "igw-1", "Attachments": []}]

        internet_gateways.load_internet_gateways(session, data, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_launch_templates(self):
        session = MagicMock()
        data = [{"LaunchTemplateId": "lt-1", "CreateTime": NOW}]

        launch_templates.load_launch_templates(session, data, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_reserved_instances(self):
        session = MagicMock()
        data = [{"ReservedInstancesId": "ri-1", "Start": NOW, "End": NOW}]

        reserved_instances.load_reserved_instances(session, data, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_volumes(self):
        session = MagicMock()
        data = [{"VolumeId": "vol-1", "region": TEST_REGION}]

        volumes.load_volumes(session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_snapshots(self):
        session = MagicMock()
        data = [{"SnapshotId": "snap-1", "StartTime": NOW, "region": TEST_REGION}]

        snapshots.load_snapshots(session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_subnets_writes_three_batches(self):
        session = MagicMock()
        data = [{"SubnetId": "subnet-1"}]

        subnets.load_subnets(session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        # subnet nodes, vpc relations, account relations
        assert session.execute_write.call_count == 3
        for call in session.execute_write.call_args_list:
            assert_batched(call, data)

    def test_vpc_peerings(self):
        session = MagicMock()
        data = [{
            "VpcPeeringConnectionId": "pcx-1",
            "AccepterVpcInfo": {"VpcId": "vpc-1", "CidrBlockSet": []},
            "RequesterVpcInfo": {"VpcId": "vpc-2", "CidrBlockSet": []},
        }]

        vpc_peerings.load_vpc_peerings(session, data, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_ec2_to_eks_links(self):
        session = MagicMock()
        instance_list = [{"InstanceId": "i-1", "EksClusterName": "c1", "EksNodeGroupName": "ng1"}]

        instances.link_ec2_to_eks(session, instance_list, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        # cluster links + node group links
        assert session.execute_write.call_count == 2
        for call in session.execute_write.call_args_list:
            assert_batched(call, instance_list)

    def test_vpc_cidr_association_set(self):
        session = MagicMock()
        vpc_data = {"CidrBlockAssociationSet": [{"AssociationId": "a-1", "CidrBlock": "10.0.0.0/16"}]}

        vpc.load_cidr_association_set(session, "vpc-1", vpc_data, "ipv4", TEST_UPDATE_TAG)

        session.run.assert_not_called()
        call = session.execute_write.call_args
        assert_batched(call, vpc_data["CidrBlockAssociationSet"])
        assert call.kwargs["VpcId"] == "vpc-1"


class TestManagedScalarWrites:
    def test_key_pairs_write_per_key_is_managed(self):
        session = MagicMock()
        data = [{"KeyName": "k1", "KeyFingerprint": "fp", "region": TEST_REGION}]

        key_pairs.load_ec2_key_pairs(session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        session.execute_write.assert_called_once()

    def test_instance_image_relations_write_is_managed(self):
        session = MagicMock()

        images.link_ec2_instances_to_images(session, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        session.execute_write.assert_called_once()

    def test_tgw_attachment_writes_are_managed(self):
        session = MagicMock()
        attachment = {"VpcId": "vpc-1", "TransitGatewayAttachmentId": "tgw-attach-1", "SubnetIds": ["subnet-1"]}

        tgw._attach_tgw_vpc_attachment_to_vpc_subnets(
            session, attachment, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
        )

        session.run.assert_not_called()
        # one write for the vpc link, one per subnet
        assert session.execute_write.call_count == 2


class TestReads:
    def test_get_images_in_use_uses_managed_read(self):
        session = MagicMock()
        session.execute_read.return_value = [{"images": ["ami-1", "ami-2"]}]

        result = images.get_images_in_use(session, TEST_REGION, TEST_ACCOUNT_ID)

        session.run.assert_not_called()
        session.execute_read.assert_called_once()
        assert result == ["ami-1", "ami-2"]
