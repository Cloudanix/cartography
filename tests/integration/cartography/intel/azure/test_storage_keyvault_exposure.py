"""
Storage account and key vault exposure: public only when public network access is
not Disabled and the firewall default action is Allow (or unknown, fail-safe).
Nodes are loaded through the real loaders and the real jobs run on Neo4j.
"""
from cartography.intel.azure import key_vaults
from cartography.intel.azure import storage
from cartography.util import run_analysis_job

SUB = 'skx-sub'
TENANT = 'skx-tenant'
WORKSPACE = 'skx-ws'
PARAMS = {
    'UPDATE_TAG': 2, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
# (name, public network access, firewall default action, expected exposed)
MATRIX = [
    ('enabled-allow', 'Enabled', 'Allow', True),
    ('disabled-allow', 'Disabled', 'Allow', False),
    ('enabled-deny', 'Enabled', 'Deny', False),
    ('enabled-unknown-acl', 'Enabled', None, True),
    ('unknown-access-allow', None, 'Allow', True),
]


def _scope(session):
    session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(:AzureSubscription{id: $sub})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB,
    )


def _exposed(session, label):
    rows = session.run(
        f"MATCH (n:{label}) WHERE n.id STARTS WITH '/subscriptions/skx-sub/' "
        "RETURN n.name AS name, coalesce(n.exposed_internet, false) AS exposed",
    )
    return {r['name']: r['exposed'] for r in rows}


def test_storage_account_exposure(neo4j_session):
    _scope(neo4j_session)
    accounts = [
        {
            'id': f'/subscriptions/skx-sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/{name}',
            'name': name, 'location': 'eastus', 'resourceGroup': 'rg', 'public_network_access': access,
            'network_rule_set': {'default_action': action} if action else None,
        }
        for name, access, action, _ in MATRIX
    ]
    storage.load_storage_account_data(neo4j_session, SUB, accounts, 1)

    run_analysis_job('azure_storage_asset_exposure.json', neo4j_session, PARAMS)

    assert _exposed(neo4j_session, 'AzureStorageAccount') == {name: exp for name, _, _, exp in MATRIX}


def test_key_vault_exposure(neo4j_session):
    _scope(neo4j_session)
    vaults = [
        {
            'id': f'/subscriptions/skx-sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}',
            'name': name, 'location': 'eastus', 'resource_group': 'rg',
            'properties': {
                'vault_uri': f'https://{name}.vault.azure.net/', 'public_network_access': access,
                'network_acls': {'default_action': action} if action else None,
            },
        }
        for name, access, action, _ in MATRIX
    ]
    key_vaults.load_key_vaults(neo4j_session, SUB, vaults, 1)

    run_analysis_job('azure_keyvault_asset_exposure.json', neo4j_session, PARAMS)

    assert _exposed(neo4j_session, 'AzureKeyVault') == {name: exp for name, _, _, exp in MATRIX}
