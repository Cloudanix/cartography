# Copyright (c) 2020, Oracle and/or its affiliates.
from cartography.intel.oci import organizations
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_WORKSPACE_ID = "ws-test-0"
TEST_UPDATE_TAG = 123456789


def test_load_oci_accounts(neo4j_session):
    accounts = {
        "profile-a": {"tenancy": "ocid1.tenancy.oc1..a"},
        "profile-b": {"tenancy": "ocid1.tenancy.oc1..b"},
    }
    organizations.load_oci_accounts(
        neo4j_session,
        accounts,
        TEST_UPDATE_TAG,
        {"WORKSPACE_ID": TEST_WORKSPACE_ID},
    )
    # identity_client omitted -> account name falls back to the profile name
    assert check_nodes(neo4j_session, "OCITenancy", ["id", "name"]) == {
        ("ocid1.tenancy.oc1..a", "profile-a"),
        ("ocid1.tenancy.oc1..b", "profile-b"),
    }
    assert check_rels(
        neo4j_session, "CloudanixWorkspace", "id", "OCITenancy", "id", "OWNER",
    ) == {
        (TEST_WORKSPACE_ID, "ocid1.tenancy.oc1..a"),
        (TEST_WORKSPACE_ID, "ocid1.tenancy.oc1..b"),
    }
