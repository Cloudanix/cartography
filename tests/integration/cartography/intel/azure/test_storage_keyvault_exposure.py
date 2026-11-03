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


def _vault(name, access, action):
    return {
        'id': f'/subscriptions/skx-sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/{name}',
        'name': name, 'location': 'eastus', 'resource_group': 'rg',
        'properties': {
            'vault_uri': f'https://{name}.vault.azure.net/', 'public_network_access': access,
            'network_acls': {'default_action': action} if action else None,
        },
    }


def test_key_vault_exposure(neo4j_session):
    _scope(neo4j_session)
    vaults = [_vault(name, access, action) for name, access, action, _ in MATRIX]
    # Azure sometimes returns a vault with no properties at all (no URI, no network settings):
    # nothing says it is public, so it stays unknown instead of counted as public.
    vaults.append({**_vault('no-properties', None, None), 'properties': {}})
    key_vaults.load_key_vaults(neo4j_session, SUB, vaults, 1)

    run_analysis_job('azure_keyvault_asset_exposure.json', neo4j_session, PARAMS)

    expected = {name: exp for name, _, _, exp in MATRIX}
    assert _exposed(neo4j_session, 'AzureKeyVault') == {**expected, 'no-properties': False}


def test_key_vault_children_do_not_inherit_exposure(neo4j_session):
    # Reading a key, secret or certificate always needs Entra ID auth, so the vault's network
    # verdict is not the child's. A flag left by the old job is cleared on the next run.
    _scope(neo4j_session)
    vault = _vault('kids', 'Enabled', 'Allow')
    key_vaults.load_key_vaults(neo4j_session, SUB, [vault], 1)
    child = {'vault_id': vault['id'], 'location': 'eastus', 'properties': {'attributes': {}}}
    key_vaults.load_key_vaults_keys(neo4j_session, SUB, [{**child, 'id': f"{vault['id']}/keys/k", 'name': 'k'}], 1)
    key_vaults.load_key_vaults_secrets(
        neo4j_session, SUB, [{**child, 'id': f"{vault['id']}/secrets/s", 'name': 's'}], 1,
    )
    key_vaults.load_key_vaults_certificates(
        neo4j_session, SUB, [{**child, 'id': f"{vault['id']}/certificates/c", 'name': 'c'}], 1,
    )
    neo4j_session.run(
        "MATCH (:AzureKeyVault{id: $id})-[:HAS_KEY|HAS_SECRET|HAS_CERTIFICATE]->(n) "
        "SET n.exposed_internet = true, n.exposed_internet_type = ['default_network_access']",
        id=vault['id'],
    )

    run_analysis_job('azure_keyvault_asset_exposure.json', neo4j_session, PARAMS)

    assert _exposed(neo4j_session, 'AzureKeyVault')['kids'] is True
    for label in ('AzureKeyVaultKey', 'AzureKeyVaultSecret', 'AzureKeyVaultCertificate'):
        assert set(_exposed(neo4j_session, label).values()) == {False}, label
