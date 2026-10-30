"""Unit tests for Compute Engine image transforms, listing, and reference resolution."""
from unittest.mock import MagicMock

import cartography.intel.gcp.images as images
from cartography.intel.gcp.images import _image_partial_uri as image_partial_uri
from cartography.intel.gcp.images import _parse_image_reference as parse_image_reference


def test_image_partial_uri_normalizes_self_link_family_and_short_form():
    self_link = "https://www.googleapis.com/compute/v1/projects/my-project/global/images/custom-1"
    assert image_partial_uri(self_link) == "projects/my-project/global/images/custom-1"

    family = "projects/debian-cloud/global/images/family/debian-12"
    assert image_partial_uri(family) == family
    parsed = parse_image_reference(family)
    assert parsed["family"] == "debian-12"
    assert parsed["project"] == "debian-cloud"

    assert image_partial_uri("global/images/custom-1", "my-project") == (
        "projects/my-project/global/images/custom-1"
    )


def test_image_region_comes_from_a_region_or_the_disk_zone():
    assert images._image_region({"storageLocations": ["us-east1"]}) == "us-east1"
    assert images._image_region({"storageLocations": ["europe-west2"]}) == "europe-west2"
    assert images._image_region({"storageLocations": ["us"]}) is None
    assert images._region_for_image({"storageLocations": ["us"]}) == "us-central1"
    assert images._region_for_image({"storageLocations": ["eu"]}) == "europe-west2"
    assert images._region_for_image({"storageLocations": ["asia"]}) == "asia-south1"
    assert images._region_for_image(
        {"storageLocations": ["us"]},
        ["https://www.googleapis.com/compute/v1/projects/p/zones/us-east1-b"],
    ) == "us-east1"
    assert images._image_region({
        "storageLocations": ["us"],
        "sourceDisk": "projects/my-project/zones/us-east1-b/disks/d1",
    }) == "us-east1"
    assert images._image_region({
        "storageLocations": ["eu"],
        "sourceDisk": "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west2-a/disks/d1",
    }) == "europe-west2"
    assert images._image_region({
        "storageLocations": ["asia"],
        "sourceDisk": "projects/p/zones/asia-southeast1-b/disks/d1",
    }) == "asia-southeast1"
    assert images._image_region({"storageLocations": ["us", "us-west1"]}) == "us-west1"
    assert images._image_region({
        "storageLocations": [],
        "sourceDisk": "projects/my-project/zones/europe-west2-a/disks/d1",
    }) == "europe-west2"
    assert images._region_from_disk_zones([
        "https://www.googleapis.com/compute/v1/projects/p/zones/us-west1-a",
        "https://www.googleapis.com/compute/v1/projects/p/zones/us-east1-b",
    ]) == "us-east1"
    assert images._image_region({}) is None


def test_transform_gcp_image_flattens_api_fields_and_drops_key_material():
    image = {
        "id": "12345",
        "name": "custom-1",
        "description": "built from disk",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/global/images/custom-1",
        "creationTimestamp": "2024-01-01T00:00:00.000-00:00",
        "status": "READY",
        "sourceType": "RAW",
        "family": "custom",
        "diskSizeGb": "10",
        "archiveSizeBytes": "1000",
        "architecture": "X86_64",
        "licenses": ["https://www.googleapis.com/compute/v1/projects/ubuntu-os-cloud/global/licenses/ubuntu-2204"],
        "licenseCodes": [123],
        "storageLocations": ["us-central1"],
        "guestOsFeatures": [{"type": "UEFI_COMPATIBLE"}, {"type": "WINDOWS"}],
        "sourceDisk": "projects/my-project/zones/us-central1-a/disks/d1",
        "sourceDiskId": "99",
        "deprecated": {
            "state": "DEPRECATED",
            "replacement": "https://www.googleapis.com/compute/v1/projects/my-project/global/images/custom-2",
            "deprecated": "2024-02-01T00:00:00.000-00:00",
        },
        "satisfiesPzs": True,
        "enableConfidentialCompute": False,
        "labelFingerprint": "abc",
        "labels": {"env": "prod"},
        "shieldedInstanceInitialState": {"pk": {"content": "not-stored"}},
        "rawDisk": {"source": "gs://bucket/disk.tar.gz", "containerType": "TAR", "sha1Checksum": "abc123"},
        "imageEncryptionKey": {
            "rawKey": "not-stored",
            "kmsKeyName": "projects/p/locations/us/keyRings/r/cryptoKeys/k",
        },
    }

    row = images.transform_gcp_image(image, "my-project")

    assert row["id"] == "projects/my-project/global/images/custom-1"
    assert row["image_id"] == "12345"
    assert row["project_id"] == "my-project"
    assert row["status"] == "READY"
    assert row["region"] == "us-central1"
    assert row["guest_os_features"] == ["UEFI_COMPATIBLE", "WINDOWS"]
    assert row["os_features"] == "WINDOWS"
    assert row["license_codes"] == ["123"]
    assert row["deprecated_state"] == "DEPRECATED"
    assert row["deprecated_replacement"].endswith("/custom-2")
    assert row["has_shielded_instance_initial_state"] is True
    assert row["raw_disk_source"] == "gs://bucket/disk.tar.gz"
    assert row["image_encryption_kms_key"].endswith("/cryptoKeys/k")
    assert "not-stored" not in row.values()
    assert row["labels"] == {"env": "prod"}
    assert row["label_pairs"] == ["env:prod"]
    assert row["consolelink"] == (
        "https://console.cloud.google.com/compute/imagesDetail/projects/my-project/global/images/custom-1"
        "?project=my-project"
    )


def test_get_compute_images_paginates():
    compute = MagicMock()
    first = MagicMock()
    second = MagicMock()
    compute.images.return_value.list.return_value = first
    first.execute.return_value = {"items": [{"name": "a"}]}
    second.execute.return_value = {"items": [{"name": "b"}]}
    compute.images.return_value.list_next.side_effect = [second, None]

    assert images.get_compute_images(compute, "my-project") == [{"name": "a"}, {"name": "b"}]


def test_resolve_referenced_images_skips_known_images_and_resolves_families():
    compute = MagicMock()
    compute.images.return_value.getFromFamily.return_value.execute.return_value = {
        "name": "debian-12-v1",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-12-v1",
    }
    known = {"projects/my-project/global/images/custom-1"}
    sources = [
        "https://www.googleapis.com/compute/v1/projects/my-project/global/images/custom-1",
        "projects/debian-cloud/global/images/family/debian-12",
    ]

    raw_images, resolutions = images.resolve_referenced_images(compute, sources, known, "my-project")

    compute.images.return_value.get.assert_not_called()
    assert raw_images[0]["name"] == "debian-12-v1"
    assert resolutions == [{
        "source_partial_uri": "projects/debian-cloud/global/images/family/debian-12",
        "image_id": "projects/debian-cloud/global/images/debian-12-v1",
        "family": "debian-12",
    }]


def test_sync_compute_images_loads_project_images_and_their_labels():
    session = MagicMock()
    compute = MagicMock()
    request = MagicMock()
    compute.images.return_value.list.return_value = request
    request.execute.return_value = {
        "items": [{
            "id": "7",
            "name": "custom-1",
            "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/global/images/custom-1",
            "labels": {"env": "prod"},
            "status": "READY",
        }],
    }
    compute.images.return_value.list_next.return_value = None

    params = {"service_labels": []}
    loaded_ids = images.sync_compute_images(session, compute, "my-project", 1, params)

    assert loaded_ids == {"projects/my-project/global/images/custom-1"}
    query = session.execute_write.call_args_list[0].args[1]
    assert "MERGE (img:GCPImage {id: item.id})" in query
    assert "MERGE (owner)-[r:RESOURCE]->(img)" in query
    assert params["service_labels"] == ["GCPImage"]
