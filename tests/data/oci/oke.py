# Copyright (c) 2020, Oracle and/or its affiliates.
# Transformed (post-transform) OCI OKE fixtures, shaped as the load_* functions expect.
TEST_COMPARTMENT_ID = "ocid1.compartment.oc1..aaaaaaaaoke00000000000000000000000000000000000000000000000000000"
TEST_REGION = "us-phoenix-1"

CLUSTERS = [
    {
        "id": "oci.oke.cluster.0",
        "ocid": "ocid1.cluster.oc1..0",
        "name": "cluster-0",
        "compartment_id": TEST_COMPARTMENT_ID,
        "kubernetes_version": "v1.29.1",
        "lifecycle_state": "ACTIVE",
        "vcn_id": "ocid1.vcn.oc1..0",
        "is_public": False,
        "region": TEST_REGION,
        "time_created": "2024-01-01T00:00:00Z",
    },
]

# node pool linked to cluster-0 (HAS_NODE_POOL) and to instance oci.instance.0
# (CONTAINS_NODE, resolved from the nested nodes[].ocid).
NODE_POOLS = [
    {
        "id": "oci.oke.pool.0",
        "ocid": "ocid1.nodepool.oc1..0",
        "name": "pool-0",
        "compartment_id": TEST_COMPARTMENT_ID,
        "cluster_id": "oci.oke.cluster.0",
        "lifecycle_state": "ACTIVE",
        "node_shape": "VM.Standard.E4.Flex",
        "size": 1,
        "region": TEST_REGION,
        "time_created": "2024-01-01T00:00:00Z",
        "nodes": [{"ocid": "oci.instance.0"}],
    },
]
