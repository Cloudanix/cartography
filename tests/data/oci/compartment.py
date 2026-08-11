# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI compartment fixtures, shaped as get_all_oci_compartments() returns.
TEST_TENANCY_ID = "ocid1.tenancy.oc1..aaaaaaaatenancy000000000000000000000000000000000000000000000000"

COMPARTMENTS = [
    {
        "id": "ocid1.compartment.oc1..comp0",
        "compartmentId": "ocid1.compartment.oc1..comp0",
        "name": "compartment-0",
        "description": "first",
        "lifecycleState": "ACTIVE",
        "timeCreated": "2024-01-01T00:00:00Z",
        "parentCompartmentId": TEST_TENANCY_ID,
    },
    {
        "id": "ocid1.compartment.oc1..comp1",
        "compartmentId": "ocid1.compartment.oc1..comp1",
        "name": "compartment-1",
        "description": "second",
        "lifecycleState": "ACTIVE",
        "timeCreated": "2024-01-01T00:00:00Z",
        "parentCompartmentId": TEST_TENANCY_ID,
    },
]
