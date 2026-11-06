"""
Unit tests for GCP compute instance VmOs/VmOsVersion derivation.
Validates that the OS name is extracted from the boot disk's source image URL.
"""
from unittest.mock import MagicMock

from cartography.intel.gcp.compute import transform_gcp_instances


def _make_instance(source_image="", guest_os_features=None):
    """Build a minimal GCP instance fixture."""
    disk = {
        "boot": True,
        "initializeParams": {
            "diskName": "disk-1",
            "sourceImage": source_image,
        },
        "guestOsFeatures": guest_os_features or [],
    }
    return {
        "id": "1234567890",
        "name": "test-instance",
        "selfLink": "https://compute.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances/test-instance",
        "zone": "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances",
        "status": "RUNNING",
        "machineType": "e2-medium",
        "disks": [disk],
        "networkInterfaces": [{
            "networkIP": "10.0.0.2",
            "subnetwork": "https://compute.googleapis.com/compute/v1/projects/my-project/regions/us-central1/subnetworks/default",
            "network": "https://compute.googleapis.com/compute/v1/projects/my-project/global/networks/default",
            "accessConfigs": [],
            "ipv6AccessConfigs": [],
        }],
        "labels": {},
        "scheduling": {},
    }


class TestGcpVmOsDerivation:
    """Verify vm_os is derived from the boot disk source image URL."""

    def test_ubuntu_from_source_image(self):
        instance = _make_instance(
            source_image="projects/ubuntu-os-cloud/global/images/ubuntu-2204-jammy-v20240101"
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert len(results) == 1
        assert results[0]["vmOs"] == "ubuntu"
        assert "ubuntu-2204-jammy" in results[0]["vmOsVersion"]

    def test_windows_from_source_image(self):
        instance = _make_instance(
            source_image="projects/windows-cloud/global/images/windows-server-2022-dc-v20240101",
            guest_os_features=[{"type": "WINDOWS"}],
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "windows"
        assert "windows-server-2022" in results[0]["vmOsVersion"]

    def test_centos_from_source_image(self):
        instance = _make_instance(
            source_image="projects/centos-cloud/global/images/centos-7-v20240101"
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "centos"

    def test_unknown_when_no_source_image(self):
        instance = _make_instance(source_image="")

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "unknown"
        assert results[0]["vmOsVersion"] is None

    def test_unknown_when_unrecognized_image(self):
        instance = _make_instance(
            source_image="projects/custom/global/images/my-custom-image-v1"
        )

        results = transform_gcp_instances([instance], MagicMock())

        assert results[0]["vmOs"] == "unknown"
        # vmOsVersion should still have the image name for manual inspection
        assert results[0]["vmOsVersion"] == "my-custom-image-v1"
