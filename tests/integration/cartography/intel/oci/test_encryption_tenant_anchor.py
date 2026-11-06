"""
KMS lookups reach existing nodes only through the syncing tenancy (AGENTS.md "Tenant isolation").
"""
import pytest

from cartography.intel.oci import encryption
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
TAG = 7


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    a, b = seed_tenancy(neo4j_session, 'kms-a'), seed_tenancy(neo4j_session, 'kms-b')
    for prefix, ids in (('kms-a', a), ('kms-b', b)):
        encryption.load_vaults(
            neo4j_session, [{'id': f'{prefix}-vault', 'compartment-id': ids['OCI_COMPARTMENT_ID']}],
            ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID'], REGION, TAG,
        )
    return a, b


def test_vault_attaches_only_to_a_compartment_of_the_syncing_tenancy(neo4j_session, tenants):
    a, b = tenants
    encryption.load_vaults(
        neo4j_session, [{'id': 'a-vault-2', 'compartment-id': b['OCI_COMPARTMENT_ID']}],
        a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG,
    )
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'kms-a-vault')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-vault-2')


def test_keys_link_only_to_a_vault_of_the_syncing_tenancy(neo4j_session, tenants):
    a, _ = tenants
    args = (a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG)
    encryption.load_keys(neo4j_session, [{'id': 'a-key'}], 'kms-a-vault', *args)
    encryption.load_keys(neo4j_session, [{'id': 'a-key-foreign'}], 'kms-b-vault', *args)
    assert linked(neo4j_session, 'kms-a-vault', 'OCI_KMS_KEY', 'a-key')
    assert not linked(neo4j_session, 'kms-b-vault', 'OCI_KMS_KEY', 'a-key-foreign')
