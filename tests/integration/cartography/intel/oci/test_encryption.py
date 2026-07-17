# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.encryption as test_data
from cartography.intel.oci import encryption
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_COMPARTMENT_ID = test_data.TEST_COMPARTMENT_ID
TEST_TENANCY_ID = test_data.TEST_TENANCY_ID
TEST_REGION = test_data.TEST_REGION
TEST_UPDATE_TAG = 123456789


def _seed_compartment(neo4j_session):
    neo4j_session.run(
        "MERGE (c:OCICompartment{id: $id}) SET c.lastupdated = $tag",
        id=TEST_COMPARTMENT_ID,
        tag=TEST_UPDATE_TAG,
    )


def test_load_vaults(neo4j_session):
    _seed_compartment(neo4j_session)
    encryption.load_vaults(
        neo4j_session, test_data.VAULTS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIKmsVault", ["id", "display_name"]) == {
        ("oci.vault.0", "vault-0"),
    }
    assert (TEST_COMPARTMENT_ID, "oci.vault.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCIKmsVault", "id", "RESOURCE",
    )


def test_load_keys_links_vault(neo4j_session):
    _seed_compartment(neo4j_session)
    encryption.load_vaults(
        neo4j_session, test_data.VAULTS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    encryption.load_keys(
        neo4j_session, test_data.KEYS, "oci.vault.0", TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIKmsKey", ["id", "display_name"]) == {
        ("oci.key.0", "key-0"),
    }
    assert ("oci.vault.0", "oci.key.0") in check_rels(
        neo4j_session, "OCIKmsVault", "id", "OCIKmsKey", "id", "OCI_KMS_KEY",
    )
