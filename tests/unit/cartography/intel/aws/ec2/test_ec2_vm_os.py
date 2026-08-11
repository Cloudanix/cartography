"""
Unit tests for VmOs and VmOsVersion derivation in EC2 instance transform.
Validates that the OS name is extracted from the AMI description and the
OS version from the AMI name, then both are included in the transform output.
"""
from unittest.mock import MagicMock, patch

from cartography.intel.aws.ec2.instances import transform_ec2_instances


def _make_reservation(instance_overrides=None, os_details=None):
    """Build a minimal reservation fixture with one instance."""
    instance = {
        "InstanceId": "i-test01",
        "PublicDnsName": "ec2-1-2-3-4.compute-1.amazonaws.com",
        "PublicIpAddress": "1.2.3.4",
        "PrivateIpAddress": "10.0.0.1",
        "ImageId": "ami-12345",
        "InstanceType": "t3.micro",
        "Monitoring": {"State": "disabled"},
        "State": {"Name": "running"},
        "LaunchTime": None,
        "Placement": {"AvailabilityZone": "us-east-1a", "Tenancy": "default"},
        "NetworkInterfaces": [],
        "BlockDeviceMappings": [],
        "Tags": [],
        "EbsOptimized": False,
    }
    if instance_overrides:
        instance.update(instance_overrides)
    if os_details is not None:
        instance["OSDetails"] = os_details
    return {
        "ReservationId": "r-test01",
        "OwnerId": "123456789012",
        "Instances": [instance],
        "region": "us-east-1",
    }


class TestVmOsDerivation:
    """Verify VmOs is derived from AMI Description using OPERATING_SYSTEMS list."""

    def test_ubuntu_os_detected(self):
        os_details = {
            "Platform": "Linux",
            "Description": "Canonical, Ubuntu, 22.04 LTS, amd64 jammy image",
            "Name": "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-20240101",
            "Architecture": "x86_64",
            "VirtualizationType": "hvm",
            "Hypervisor": "xen",
        }
        reservation = _make_reservation(os_details=os_details)

        with patch(
            "cartography.intel.aws.ec2.instances.get_roles_from_instance_profile",
            return_value=[],
        ):
            ec2_data = transform_ec2_instances(
                MagicMock(), [reservation], "us-east-1", "123456789012",
            )

        instance = ec2_data.instance_list[0]
        assert instance["VmOs"] == "ubuntu"
        assert "ubuntu-jammy-22.04" in instance["VmOsVersion"]

    def test_amazon_linux_detected(self):
        os_details = {
            "Platform": "Linux",
            "Description": "Amazon Linux 2023 AMI 2023.6.20241212.0 x86_64",
            "Name": "al2023-ami-2023.6.20241212.0-kernel-6.1-x86_64",
            "Architecture": "x86_64",
            "VirtualizationType": "hvm",
            "Hypervisor": "xen",
        }
        reservation = _make_reservation(os_details=os_details)

        with patch(
            "cartography.intel.aws.ec2.instances.get_roles_from_instance_profile",
            return_value=[],
        ):
            ec2_data = transform_ec2_instances(
                MagicMock(), [reservation], "us-east-1", "123456789012",
            )

        instance = ec2_data.instance_list[0]
        assert instance["VmOs"] == "amazon"
        assert "al2023" in instance["VmOsVersion"]

    def test_windows_detected(self):
        os_details = {
            "Platform": "Windows",
            "Description": "Microsoft Windows Server 2022 Full Locale English AMI",
            "Name": "Windows_Server-2022-English-Full-Base-2024.01.01",
            "Architecture": "x86_64",
            "VirtualizationType": "hvm",
            "Hypervisor": "xen",
        }
        reservation = _make_reservation(os_details=os_details)

        with patch(
            "cartography.intel.aws.ec2.instances.get_roles_from_instance_profile",
            return_value=[],
        ):
            ec2_data = transform_ec2_instances(
                MagicMock(), [reservation], "us-east-1", "123456789012",
            )

        instance = ec2_data.instance_list[0]
        assert instance["VmOs"] == "windows"
        assert "Windows_Server-2022" in instance["VmOsVersion"]

    def test_unknown_os_when_no_details(self):
        """When OSDetails is absent (describe_images failed), VmOs should be 'Unknown'."""
        reservation = _make_reservation(os_details={})

        with patch(
            "cartography.intel.aws.ec2.instances.get_roles_from_instance_profile",
            return_value=[],
        ):
            ec2_data = transform_ec2_instances(
                MagicMock(), [reservation], "us-east-1", "123456789012",
            )

        instance = ec2_data.instance_list[0]
        assert instance["VmOs"] == "Unknown"
        assert instance["VmOsVersion"] == "Unknown"

    def test_vmos_fields_in_model(self):
        """Verify EC2InstanceNodeProperties includes vmos and vmosversion."""
        from cartography.models.aws.ec2.instances import EC2InstanceNodeProperties
        props = EC2InstanceNodeProperties()
        assert hasattr(props, "vmos")
        assert hasattr(props, "vmosversion")
        assert props.vmos.name == "VmOs"
        assert props.vmosversion.name == "VmOsVersion"
