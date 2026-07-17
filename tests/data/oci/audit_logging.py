# Copyright (c) 2020, Oracle and/or its affiliates.
# Raw OCI Logging API fixtures (hyphenated keys), as the load_* functions receive them.
TEST_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaalog000000000000000000000000000000000000000000000000000000"
TEST_TENANCY_ID = "ocid1.tenancy.oc1..log"
TEST_REGION = "us-phoenix-1"

LOG_GROUPS = [
    {
        "id": "oci.lg.0",
        "display-name": "lg-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "description": "a log group",
        "lifecycle-state": "ACTIVE",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

LOGS = [
    {
        "id": "oci.log.0",
        "display-name": "log-0",
        "log-type": "SERVICE",
        "is-enabled": True,
        "lifecycle-state": "ACTIVE",
        "retention-duration": 30,
        "compartment-id": TEST_COMPARTMENT_ID,
        "configuration": {
            "source": {
                "service": "objectstorage",
                "resource": "bkt",
                "category": "write",
            },
        },
        "time-created": "2024-01-01T00:00:00Z",
    },
]

# ServiceSummary shape: resource-types is a list of dicts with a name.
LOGGING_SERVICES = [
    {
        "id": "objectstorage",
        "name": "Object Storage",
        "namespace": "ns",
        "resource-types": [{"name": "bucket"}],
    },
]
