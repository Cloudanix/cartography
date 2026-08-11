# Copyright (c) 2020, Oracle and/or its affiliates.
# Raw OCI KMS API fixtures (hyphenated keys), as load_vaults/load_keys receive them.
TEST_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaakms000000000000000000000000000000000000000000000000000000"
TEST_TENANCY_ID = "ocid1.tenancy.oc1..kms"
TEST_REGION = "us-phoenix-1"

VAULTS = [
    {
        "id": "oci.vault.0",
        "display-name": "vault-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "vault-type": "DEFAULT",
        "lifecycle-state": "ACTIVE",
        "crypto-endpoint": "https://crypto.example",
        "management-endpoint": "https://mgmt.example",
        "time-created": "2024-01-01T00:00:00Z",
    },
]

KEYS = [
    {
        "id": "oci.key.0",
        "display-name": "key-0",
        "compartment-id": TEST_COMPARTMENT_ID,
        "algorithm": "AES",
        "protection-mode": "HSM",
        "lifecycle-state": "ENABLED",
        "current-key-version": "v1",
        "time-created": "2024-01-01T00:00:00Z",
    },
]
