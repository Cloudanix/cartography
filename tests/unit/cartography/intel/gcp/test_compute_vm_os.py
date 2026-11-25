"""
Unit tests for GCP compute instance VmOs / VmOsVersion / Platform / Architecture.

instances.list does not return initializeParams.sourceImage. The OS is read from the
boot-disk license (and from the source image when a create response still has it),
the same fields EC2 stores from the AMI.
"""
from unittest.mock import MagicMock

from cartography.intel.gcp.compute import transform_gcp_instances


def _make_instance(source_image="", guest_os_features=None, licenses=None, architecture=None, cpu_platform=None):
    """Build a minimal GCP instance fixture."""
    disk = {
        "boot": True,
        "guestOsFeatures": guest_os_features or [],
    }
    if source_image:
        disk["initializeParams"] = {"diskName": "disk-1", "sourceImage": source_image}
    else:
        disk["initializeParams"] = {"diskName": "disk-1"}
    if licenses is not None:
        disk["licenses"] = licenses
    if architecture:
        disk["architecture"] = architecture
    instance = {
        "id": "1234567890",
        "name": "test-instance",
        "selfLink": (
            "https://compute.googleapis.com/compute/v1/projects/my-project/"
            "zones/us-central1-a/instances/test-instance"
        ),
        "zone": "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances",
        "status": "RUNNING",
        "machineType": "e2-medium",
        "disks": [disk],
        "networkInterfaces": [{
            "networkIP": "10.0.0.2",
            "subnetwork": (
                "https://compute.googleapis.com/compute/v1/projects/my-project/"
                "regions/us-central1/subnetworks/default"
            ),
            "network": "https://compute.googleapis.com/compute/v1/projects/my-project/global/networks/default",
            "accessConfigs": [],
            "ipv6AccessConfigs": [],
        }],
        "labels": {},
        "scheduling": {},
    }
    if cpu_platform:
        instance["cpuPlatform"] = cpu_platform
    return instance


class TestGcpVmOsDerivation:
    """Verify vm_os, version, platform, and architecture."""

    def test_ubuntu_from_source_image(self):
        instance = _make_instance(
            source_image="projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20240101",
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert len(results) == 1
        assert results[0]["vmOs"] == "ubuntu"
        assert results[0]["vmOsVersion"] == "22.04"
        assert results[0]["platform"] == "Linux"

    def test_windows_from_source_image(self):
        instance = _make_instance(
            source_image="projects/windows-cloud/global/images/windows-server-2022-dc-v20240101",
            guest_os_features=[{"type": "WINDOWS"}],
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "windows"
        assert results[0]["vmOsVersion"] == "2022"
        assert results[0]["platform"] == "Windows"

    def test_centos_from_source_image(self):
        instance = _make_instance(
            source_image="projects/centos-cloud/global/images/centos-7-v20240101",
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "centos"
        assert results[0]["vmOsVersion"] == "7"

    def test_ubuntu_from_license_when_source_image_absent(self):
        """The shape instances.list actually returns: a license, no initializeParams.sourceImage."""
        instance = _make_instance(
            licenses=[
                "https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-1404-trusty",
            ],
            cpu_platform="Intel Haswell",
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "ubuntu"
        assert results[0]["vmOsVersion"] == "14.04"
        assert results[0]["platform"] == "Linux"
        assert results[0]["architecture"] == "x86_64"

    def test_rhel_and_debian_and_cos_licenses(self):
        rhel = transform_gcp_instances([
            _make_instance(licenses=[
                "https://www.googleapis.com/compute/v1/projects/rhel-cloud/global/licenses/rhel-9",
            ]),
        ], MagicMock())
        debian = transform_gcp_instances([
            _make_instance(licenses=[
                "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-12-bookworm",
            ]),
        ], MagicMock())
        cos = transform_gcp_instances([
            _make_instance(
                source_image="projects/cos-cloud/global/images/cos-stable-109-17800-0-45",
                cpu_platform="Ampere Altra",
            ),
        ], MagicMock())

        assert rhel[0]["vmOs"] == "redhat"
        assert rhel[0]["vmOsVersion"] == "9"
        assert debian[0]["vmOs"] == "debian"
        assert debian[0]["vmOsVersion"] == "12"
        assert cos[0]["vmOs"] == "cos"
        assert cos[0]["vmOsVersion"] == "109"
        assert cos[0]["architecture"] == "arm64"

    def test_architecture_from_boot_disk(self):
        instance = _make_instance(architecture="ARM64", cpu_platform="Intel Haswell")

        results = transform_gcp_instances([instance], MagicMock())

        # The disk value wins over cpuPlatform.
        assert results[0]["architecture"] == "arm64"

    def test_unknown_when_no_source_image_or_license(self):
        instance = _make_instance(source_image="")

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "Unknown"
        assert results[0]["vmOsVersion"] == "Unknown"
        assert results[0]["platform"] == "Linux"
        assert results[0]["architecture"] is None

    def test_unknown_when_unrecognized_image(self):
        instance = _make_instance(
            source_image="projects/custom/global/images/my-custom-image-v1",
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "Unknown"
        assert results[0]["vmOsVersion"] == "Unknown"

    def test_image_date_stamp_is_not_the_ubuntu_version(self):
        instance = _make_instance(
            source_image="projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20240606",
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOsVersion"] == "24.04"
