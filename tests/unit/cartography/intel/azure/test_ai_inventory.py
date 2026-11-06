"""
Transform tests for the Azure AI inventory syncs, built from real SDK models
deserialized from ARM payloads, so a change in how the SDK flattens or nests
properties shows up here instead of as silently-null graph properties.
"""
from azure.mgmt.cognitiveservices import models as cs_models
from azure.mgmt.machinelearningservices import models as ml_models

from cartography.intel.azure import cognitiveservices
from cartography.intel.azure import machinelearning

SUB = '/subscriptions/00000000-0000-0000-0000-000000000001'
RG = f'{SUB}/resourceGroups/rg-ai'
COMMON_JOB_PARAMETERS = {'Azure_Primary_AD_Domain_Name': 'example.onmicrosoft.com'}


def test_transform_workspaces_reads_flattened_properties():
    payload = {
        'id': f'{RG}/providers/Microsoft.MachineLearningServices/workspaces/ws1',
        'name': 'ws1',
        'type': 'Microsoft.MachineLearningServices/workspaces',
        'location': 'eastus',
        'kind': 'Hub',
        'identity': {'type': 'SystemAssigned', 'principalId': 'pid-1'},
        'properties': {
            'friendlyName': 'Workspace One',
            'publicNetworkAccess': 'Disabled',
            'keyVault': f'{RG}/providers/Microsoft.KeyVault/vaults/kv1',
            'storageAccount': f'{RG}/providers/Microsoft.Storage/storageAccounts/sa1',
            'containerRegistry': f'{RG}/providers/Microsoft.ContainerRegistry/registries/acr1',
            'applicationInsights': f'{RG}/providers/Microsoft.Insights/components/ai1',
        },
    }
    ws = ml_models.Workspace.deserialize(payload).as_dict()

    [out] = machinelearning.transform_workspaces([ws], None, COMMON_JOB_PARAMETERS)

    assert out['friendly_name'] == 'Workspace One'
    assert out['public_network_access'] == 'Disabled'
    assert out['key_vault'] == f'{RG}/providers/Microsoft.KeyVault/vaults/kv1'
    assert out['storage_account'] == f'{RG}/providers/Microsoft.Storage/storageAccounts/sa1'
    assert out['container_registry'].endswith('/registries/acr1')
    assert out['application_insights'].endswith('/components/ai1')
    assert out['principal_id'] == 'pid-1'
    assert out['resource_group'] == 'rg-ai'


def test_transform_accounts_keeps_cmk_vault_url():
    payload = {
        'id': f'{RG}/providers/Microsoft.CognitiveServices/accounts/oai1',
        'name': 'oai1',
        'kind': 'OpenAI',
        'location': 'eastus',
        'sku': {'name': 'S0'},
        'properties': {
            'endpoint': 'https://oai1.openai.azure.com/',
            'customSubDomainName': 'oai1',
            'publicNetworkAccess': 'Enabled',
            'encryption': {
                'keySource': 'Microsoft.KeyVault',
                'keyVaultProperties': {
                    'keyName': 'cmk', 'keyVersion': 'v1', 'keyVaultUri': 'https://kv1.vault.azure.net/',
                },
            },
        },
    }
    account = cs_models.Account.deserialize(payload).as_dict()

    [out] = cognitiveservices.transform_accounts([account], None, COMMON_JOB_PARAMETERS)

    assert out['key_source'] == 'Microsoft.KeyVault'
    assert out['key_vault_uri'] == 'https://kv1.vault.azure.net/'
    assert out['endpoint'] == 'https://oai1.openai.azure.com/'
    assert out['custom_sub_domain_name'] == 'oai1'
    assert out['public_network_access'] == 'Enabled'
