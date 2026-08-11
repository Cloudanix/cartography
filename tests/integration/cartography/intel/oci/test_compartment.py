# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.compartment as test_data
from cartography.intel.oci import compartment
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_TENANCY_ID = test_data.TEST_TENANCY_ID
TEST_UPDATE_TAG = 123456789


def test_load_oci_compartments(neo4j_session):
    compartment.load_oci_compartments(
        neo4j_session, TEST_TENANCY_ID, test_data.COMPARTMENTS, TEST_UPDATE_TAG, {},
    )
    assert check_nodes(neo4j_session, "OCICompartment", ["id", "name"]) == {
        ("ocid1.compartment.oc1..comp0", "compartment-0"),
        ("ocid1.compartment.oc1..comp1", "compartment-1"),
    }
    # tenancy owns each compartment
    assert check_rels(
        neo4j_session, "OCITenancy", "id", "OCICompartment", "id", "OWNER",
    ) == {
        (TEST_TENANCY_ID, "ocid1.compartment.oc1..comp0"),
        (TEST_TENANCY_ID, "ocid1.compartment.oc1..comp1"),
    }
