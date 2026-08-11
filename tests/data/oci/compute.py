# Copyright (c) 2020, Oracle and/or its affiliates.
# Raw OCI Compute API fixtures (hyphenated keys), as the load_* functions receive them.
TEST_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaacmp000000000000000000000000000000000000000000000000000000"
TEST_TENANCY_ID = "ocid1.tenancy.oc1..cmp"
TEST_REGION = "us-phoenix-1"

INSTANCES = [
    {
        "id": "oci.instance.0",
        "display-name": "instance-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "availability-domain": "AD-1",
        "fault-domain": "FD-1",
        "shape": "VM.Standard.E4.Flex",
        "lifecycle-state": "RUNNING",
        "image-id": "oci.image.0",
        "instance-options": {"are-legacy-imds-endpoints-disabled": True},
        "platform-config": {"is-secure-boot-enabled": True},
        "launch-options": {"is-pv-encryption-in-transit-enabled": False},
        "agent-config": {"is-monitoring-disabled": False},
        "time-created": "2024-01-01T00:00:00Z",
    },
]

VNIC_ATTACHMENTS = [
    {
        "id": "oci.vnicatt.0",
        "display-name": "vnicatt-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "availability-domain": "AD-1",
        "lifecycle-state": "ATTACHED",
        "vnic-id": "oci.vnic.0",
        "subnet-id": "oci.subnet.0",
        "nic-index": 0,
        "instance-id": "oci.instance.0",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

IMAGES = [
    {
        "id": "oci.image.0",
        "display-name": "image-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "operating-system": "Oracle Linux",
        "operating-system-version": "8",
        "lifecycle-state": "AVAILABLE",
        "size-in-mbs": 47694,
        "time-created": "2024-01-01T00:00:00Z",
    },
]

BOOT_VOLUME_ATTACHMENTS = [
    {
        "id": "oci.bva.0",
        "display-name": "bva-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "availability-domain": "AD-1",
        "lifecycle-state": "ATTACHED",
        "boot-volume-id": "oci.bootvol.0",
        "instance-id": "oci.instance.0",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

VOLUME_ATTACHMENTS = [
    {
        "id": "oci.va.0",
        "display-name": "va-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "availability-domain": "AD-1",
        "lifecycle-state": "ATTACHED",
        "volume-id": "oci.blockvol.0",
        "attachment-type": "paravirtualized",
        "is-read-only": False,
        "instance-id": "oci.instance.0",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

BOOT_VOLUMES = [
    {
        "id": "oci.bootvol.0",
        "display-name": "bootvol-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "availability-domain": "AD-1",
        "lifecycle-state": "AVAILABLE",
        "size-in-gbs": 50,
        "kms-key-id": None,
        "is-hydrated": True,
        "vpus-per-gb": 10,
        "image-id": "oci.image.0",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

BLOCK_VOLUMES = [
    {
        "id": "oci.blockvol.0",
        "display-name": "blockvol-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "availability-domain": "AD-1",
        "lifecycle-state": "AVAILABLE",
        "size-in-gbs": 100,
        "kms-key-id": None,
        "is-hydrated": True,
        "vpus-per-gb": 10,
        "time-created": "2024-01-01T00:00:00Z",
    },
]
