from cartography.intel.azure import key_vaults
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

VAULT_A = arm_id(SUB_A, 'Microsoft.KeyVault/vaults/kv')
VAULT_B = arm_id(SUB_B, 'Microsoft.KeyVault/vaults/kv')
# An id the API returned while syncing SUB_A that names SUB_B: its subscription segment is not an anchor.
VAULT_FOREIGN = arm_id(SUB_B, 'Microsoft.KeyVault/vaults/kv-foreign')


def test_key_vault_links_stay_in_the_syncing_subscription(neo4j_session):
    seed_customers(neo4j_session)
    seed_node(neo4j_session, SUB_B, 'AzureKeyVault', VAULT_B)

    key_vaults.load_key_vaults(
        neo4j_session, SUB_A, [{'id': VAULT_A, 'name': 'kv'}, {'id': VAULT_FOREIGN, 'name': 'kv-foreign'}],
        UPDATE_TAG,
    )
    children = [
        (key_vaults.load_key_vaults_keys, 'AzureKeyVaultKey', 'HAS_KEY'),
        (key_vaults.load_key_vaults_secrets, 'AzureKeyVaultSecret', 'HAS_SECRET'),
        (key_vaults.load_key_vaults_certificates, 'AzureKeyVaultCertificate', 'HAS_CERTIFICATE'),
    ]
    for load, label, _ in children:
        load(
            neo4j_session, SUB_A,
            [{'id': f'{VAULT_A}/{label}/own', 'vault_id': VAULT_A}, {'id': f'{VAULT_A}/{label}/x', 'vault_id': VAULT_B}],
            UPDATE_TAG,
        )

    # Resource group: the syncing subscription's group of that name, never the one the id points at.
    assert resource_group_of(neo4j_session, 'AzureKeyVault', VAULT_A) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureKeyVault', VAULT_FOREIGN) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureKeyVault', VAULT_B) == set()
    for _, label, rel in children:
        assert linked_ids(neo4j_session, 'AzureKeyVault', VAULT_A, rel, label) == {f'{VAULT_A}/{label}/own'}
        assert linked_ids(neo4j_session, 'AzureKeyVault', VAULT_B, rel, label) == set()
