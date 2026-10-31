"""
Key vault fetchers fed real SDK models: the network ACL default action and
vault URI the loader and exposure job read must arrive.
"""
from unittest.mock import MagicMock

from azure.mgmt.keyvault import models

from cartography.intel.azure import key_vaults

PARAMS = {'UPDATE_TAG': 1}
KV_ID = '/subscriptions/00-00/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv'


def test_vault_network_acls_and_uri_arrive():
    client = MagicMock()
    client.vaults.list_by_subscription.return_value = [
        models.Vault({
            'id': KV_ID, 'name': 'kv', 'location': 'eastus',
            'systemData': {'createdAt': '2026-01-01T00:00:00Z'},
            'properties': {
                'tenantId': '00000000-0000-0000-0000-000000000000',
                'sku': {'family': 'A', 'name': 'standard'},
                'vaultUri': 'https://kv.vault.azure.net/',
                'publicNetworkAccess': 'Disabled',
                'networkAcls': {'defaultAction': 'Deny'},
            },
        }),
    ]

    [vault] = key_vaults.transform_key_vaults(key_vaults.get_key_vaults_list(client), None, PARAMS)

    assert vault['properties']['network_acls']['default_action'] == 'Deny'
    assert vault['properties']['public_network_access'] == 'Disabled'
    assert vault['properties']['vault_uri'] == 'https://kv.vault.azure.net/'
    assert vault['created_on'] == '2026-01-01T00:00:00Z'
    assert vault['resource_group'] == 'rg'


def test_keys_and_secrets_arrive():
    client = MagicMock()
    client.keys.list.return_value = [
        models.Key({
            'id': f'{KV_ID}/keys/k', 'name': 'k',
            'properties': {'keyUri': 'https://kv.vault.azure.net/keys/k', 'attributes': {'enabled': True}},
        }),
    ]
    client.secrets.list.return_value = [
        models.Secret({
            'id': f'{KV_ID}/secrets/s', 'name': 's',
            'properties': {'secretUri': 'https://kv.vault.azure.net/secrets/s', 'attributes': {'enabled': True}},
        }),
    ]
    vault = {'resource_group': 'rg', 'name': 'kv'}

    [key] = key_vaults.get_key_vault_keys_list(client, vault)
    [secret] = key_vaults.get_key_vault_secrets(client, vault)

    assert key['key_uri'] == 'https://kv.vault.azure.net/keys/k'
    assert key['attributes']['enabled'] is True
    assert secret['properties']['secret_uri'] == 'https://kv.vault.azure.net/secrets/s'
    assert secret['properties']['attributes']['enabled'] is True
