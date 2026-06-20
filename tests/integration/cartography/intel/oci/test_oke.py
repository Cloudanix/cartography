# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.oke as test_data
from cartography.intel.oci import oke
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_COMPARTMENT_ID = test_data.TEST_COMPARTMENT_ID
TEST_UPDATE_TAG = 123456789


def _seed(neo4j_session):
    neo4j_session.run(
        "MERGE (c:OCICompartment{id: $id}) SET c.lastupdated = $tag",
        id=TEST_COMPARTMENT_ID,
        tag=TEST_UPDATE_TAG,
    )
    # CONTAINS_NODE matches an existing OCIInstance keyed on the node ocid.
    neo4j_session.run(
        "MERGE (i:OCIInstance{id: $id}) SET i.lastupdated = $tag",
        id="oci.instance.0",
        tag=TEST_UPDATE_TAG,
    )


def test_load_clusters(neo4j_session):
    _seed(neo4j_session)
    oke.load_clusters(
        neo4j_session, test_data.CLUSTERS, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIOKECluster", ["id"]) == {("oci.oke.cluster.0",)}
    assert (TEST_COMPARTMENT_ID, "oci.oke.cluster.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCIOKECluster", "id", "RESOURCE",
    )


def test_load_node_pools_links_cluster_and_compute(neo4j_session):
    _seed(neo4j_session)
    oke.load_clusters(
        neo4j_session, test_data.CLUSTERS, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    oke.load_node_pools(
        neo4j_session, test_data.NODE_POOLS, TEST_COMPARTMENT_ID, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIOKENodePool", ["id"]) == {("oci.oke.pool.0",)}
    # node pool -> cluster
    assert ("oci.oke.cluster.0", "oci.oke.pool.0") in check_rels(
        neo4j_session, "OCIOKECluster", "id", "OCIOKENodePool", "id", "HAS_NODE_POOL",
    )
    # node pool -> compute instance (resolved from nested nodes[].ocid)
    assert ("oci.oke.pool.0", "oci.instance.0") in check_rels(
        neo4j_session, "OCIOKENodePool", "id", "OCIInstance", "id", "CONTAINS_NODE",
    )
