# Copyright (c) 2020, Oracle and/or its affiliates.
# Transformed (post-transform) OCI storage fixtures, shaped as the load_* functions expect.
TEST_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaastorage0000000000000000000000000000000000000000000000000"
TEST_REGION = "us-phoenix-1"


# A larger-than-one-batch (>500) bucket list to exercise load_graph_data's
# 500-row batching across a chunk boundary.
def bucket_list(n: int) -> list:
    return [
        {
            "id": f"oci.bucket.{i}",
            "ocid": f"ocid1.bucket.oc1..{i}",
            "name": f"bucket-{i}",
            "namespace": "ns",
            "compartment_id": TEST_COMPARTMENT_ID,
            "public_access_type": "NoPublicAccess",
            "kms_key_id": None,
            "region": TEST_REGION,
            "time_created": "2024-01-01T00:00:00Z",
        }
        for i in range(n)
    ]


BLOCK_VOLUMES = [
    {
        "id": "oci.blockvol.0",
        "ocid": "ocid1.volume.oc1..0",
        "display_name": "block-vol-0",
        "compartment_id": TEST_COMPARTMENT_ID,
        "lifecycle_state": "AVAILABLE",
        "kms_key_id": None,
        "region": TEST_REGION,
        "time_created": "2024-01-01T00:00:00Z",
    },
]

BOOT_VOLUMES = [
    {
        "id": "oci.bootvol.0",
        "ocid": "ocid1.bootvolume.oc1..0",
        "display_name": "boot-vol-0",
        "compartment_id": TEST_COMPARTMENT_ID,
        "lifecycle_state": "AVAILABLE",
        "kms_key_id": None,
        "region": TEST_REGION,
        "time_created": "2024-01-01T00:00:00Z",
    },
]

# One backup off a block volume, one off a boot volume, to exercise both link passes.
VOLUME_BACKUPS = [
    {
        "id": "oci.backup.block.0",
        "ocid": "ocid1.volumebackup.oc1..b0",
        "display_name": "backup-block-0",
        "compartment_id": TEST_COMPARTMENT_ID,
        "source_kind": "BLOCK",
        "parent_volume_id": "ocid1.volume.oc1..0",
        "region": TEST_REGION,
        "time_created": "2024-01-01T00:00:00Z",
    },
    {
        "id": "oci.backup.boot.0",
        "ocid": "ocid1.bootvolumebackup.oc1..bb0",
        "display_name": "backup-boot-0",
        "compartment_id": TEST_COMPARTMENT_ID,
        "source_kind": "BOOT",
        "parent_volume_id": "ocid1.bootvolume.oc1..0",
        "region": TEST_REGION,
        "time_created": "2024-01-01T00:00:00Z",
    },
]

FILE_SYSTEMS = [
    {
        "id": "oci.fs.0",
        "ocid": "ocid1.filesystem.oc1..0",
        "display_name": "fs-0",
        "compartment_id": TEST_COMPARTMENT_ID,
        "lifecycle_state": "ACTIVE",
        "kms_key_id": None,
        "region": TEST_REGION,
        "time_created": "2024-01-01T00:00:00Z",
    },
]

MOUNT_TARGETS = [
    {
        "id": "oci.mt.0",
        "ocid": "ocid1.mounttarget.oc1..0",
        "display_name": "mt-0",
        "compartment_id": TEST_COMPARTMENT_ID,
        "lifecycle_state": "ACTIVE",
        "export_set_id": "ocid1.exportset.oc1..0",
        "subnet_id": "ocid1.subnet.oc1..0",
        "region": TEST_REGION,
        "time_created": "2024-01-01T00:00:00Z",
    },
]

EXPORTS = [
    {
        "id": "oci.export.0",
        "ocid": "ocid1.export.oc1..0",
        "export_set_id": "ocid1.exportset.oc1..0",
        "file_system_id": "oci.fs.0",
        "path": "/fs0",
        "lifecycle_state": "ACTIVE",
        "time_created": "2024-01-01T00:00:00Z",
    },
]
