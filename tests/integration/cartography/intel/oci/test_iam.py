# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.iam
from cartography.intel.oci import iam
from cartography.intel.oci import utils
from tests.integration.util import check_nodes
from tests.integration.util import check_rels


TEST_TENANCY_ID = "ocid1.user.oc1..nqilyrb1l5t6gnmlcjgeim8q47vccnklev8k2ud9skn78eapu116oyv9wcr0"
TEST_REGION = 'us-phoenix-1'
TEST_UPDATE_TAG = 123456789


def test_load_users(neo4j_session):
    data = tests.data.oci.iam.LIST_USERS['Users']

    iam.load_users(
        neo4j_session,
        data,
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )


def test_load_groups(neo4j_session):
    data = tests.data.oci.iam.LIST_GROUPS['Groups']

    iam.load_groups(
        neo4j_session,
        data,
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )


def test_load_policies(neo4j_session):
    data = tests.data.oci.iam.LIST_POLICIES['Policies']

    iam.load_policies(
        neo4j_session,
        data,
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )


def test_load_compartments(neo4j_session):
    data = tests.data.oci.iam.LIST_COMPARTMENTS['Compartments']

    iam.load_compartments(
        neo4j_session,
        data,
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )


def test_load_users_managed_type(neo4j_session):
    iam.load_users(
        neo4j_session, tests.data.oci.iam.LIST_USERS['Users'], TEST_TENANCY_ID, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, 'OCIUser', ['name', 'managed_type']) == {
        ('example-user-0', 'custom'),
        ('example-user-1', 'custom'),
    }


def test_load_groups_managed_type(neo4j_session):
    iam.load_groups(
        neo4j_session,
        tests.data.oci.iam.LIST_GROUPS['Groups'] + tests.data.oci.iam.PREDEFINED_GROUPS['Groups'],
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, 'OCIGroup', ['name', 'managed_type']) == {
        ('example-group-0', 'custom'),
        ('example-group-1', 'custom'),
        ('Administrators', 'predefined'),
    }


def test_load_policies_managed_type(neo4j_session):
    iam.load_policies(
        neo4j_session,
        tests.data.oci.iam.LIST_POLICIES['Policies'] + tests.data.oci.iam.PREDEFINED_POLICIES['Policies'],
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, 'OCIPolicy', ['name', 'managed_type']) == {
        ('example-policy-0', 'custom'),
        ('example-policy-1', 'custom'),
        ('Tenant Admin Policy', 'predefined'),
    }


def test_load_compartments_managed_type(neo4j_session):
    iam.load_compartments(
        neo4j_session,
        tests.data.oci.iam.LIST_COMPARTMENTS['Compartments'] + tests.data.oci.iam.PREDEFINED_COMPARTMENTS['Compartments'],
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, 'OCICompartment', ['name', 'managed_type']) == {
        ('example-compartment-0', 'custom'),
        ('example-compartment-1', 'custom'),
        ('ManagedCompartmentForPaaS', 'predefined'),
    }


def test_load_group_memberships(neo4j_session):
    group_memberships = tests.data.oci.iam.LIST_GROUP_MEMBERSHIPS
    groups = list(
        utils.get_groups_in_tenancy(neo4j_session, TEST_TENANCY_ID),
    )
    data = {group["ocid"]: group_memberships for group in groups}
    iam.load_compartments(
        neo4j_session,
        data,
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )


def test_load_group_memberships_links_users(neo4j_session):
    # Load users and the group first, then membership edges; assert both users
    # are wired to the group via MEMBER_OCID_GROUP through the batched loader.
    iam.load_users(
        neo4j_session, tests.data.oci.iam.LIST_USERS['Users'], TEST_TENANCY_ID, TEST_UPDATE_TAG,
    )
    iam.load_groups(
        neo4j_session, tests.data.oci.iam.LIST_GROUPS['Groups'], TEST_TENANCY_ID, TEST_UPDATE_TAG,
    )
    group_ocid = "ocid1.group.oc1..wa03xlg35zi0tb33qyrjteen36zrkauzhjz8pi0yzt4d2b78uo745h5ze6at"
    iam.load_group_memberships(
        neo4j_session,
        {group_ocid: tests.data.oci.iam.LIST_GROUP_MEMBERSHIPS},
        TEST_UPDATE_TAG,
    )
    assert check_rels(
        neo4j_session, "OCIUser", "id", "OCIGroup", "id", "MEMBER_OCID_GROUP",
    ) == {
        ("ocid1.user.oc1..m5oaceraqeiq47zqstzy6ickbbfkw7vg4srozp4sskn78eapu116oyv9wcr0", group_ocid),
        ("ocid1.user.oc1..srozp4sskn78eapu116oyv9wcr06ickbbfkw7vg4m5oaceraqeiq47zqstzy", group_ocid),
    }


def test_load_region_subscriptions(neo4j_session):
    neo4j_session.run(
        "MERGE (t:OCITenancy{id: $id}) SET t.lastupdated = $tag",
        id=TEST_TENANCY_ID,
        tag=TEST_UPDATE_TAG,
    )
    iam.load_region_subscriptions(
        neo4j_session,
        tests.data.oci.iam.LIST_REGION_SUBSCRIPTIONS['RegionSubscriptions'],
        TEST_TENANCY_ID,
        TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIRegion", ["id", "name"]) == {
        ("PHX", "us-phoenix-1"),
        ("IAD", "us-ashburn-1"),
    }
    assert check_rels(
        neo4j_session, "OCITenancy", "id", "OCIRegion", "id", "OCI_REGION_SUBSCRIPTION",
    ) == {
        (TEST_TENANCY_ID, "PHX"),
        (TEST_TENANCY_ID, "IAD"),
    }
