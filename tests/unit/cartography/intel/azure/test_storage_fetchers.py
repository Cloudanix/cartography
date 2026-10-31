"""
Storage fetchers fed real SDK models: the network ACL default action, public
network access and blob public access must reach the loaders.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

from azure.mgmt.storage import models

from cartography.intel.azure import storage

PARAMS = {'UPDATE_TAG': 1}
SA_ID = '/subscriptions/00-00/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa'


def _account() -> models.StorageAccount:
    return models.StorageAccount({
        'id': SA_ID, 'name': 'sa', 'location': 'eastus', 'kind': 'StorageV2',
        'properties': {
            'networkAcls': {'defaultAction': 'Deny'},
            'allowBlobPublicAccess': True,
            'publicNetworkAccess': 'Disabled',
        },
    })


def test_storage_account_network_fields_arrive():
    client = MagicMock()
    client.storage_accounts.list.return_value = [_account()]

    with patch.object(storage, 'get_client', return_value=client):
        [account] = storage.get_storage_account_list(MagicMock(), '00-00', None, PARAMS)

    assert account['network_rule_set']['default_action'] == 'Deny'
    assert account['allowBlobPublicAccess'] is True
    assert account['public_network_access'] == 'Disabled'
    assert account['resourceGroup'] == 'rg'


def test_blob_containers_and_services_arrive():
    client = MagicMock()
    client.blob_containers.list.return_value = [
        models.ListContainerItem({
            'id': f'{SA_ID}/blobServices/default/containers/c1', 'name': 'c1',
            'properties': {'publicAccess': 'Container'},
        }),
    ]
    client.queue_services.list.return_value = models.ListQueueServices({
        'value': [{'id': f'{SA_ID}/queueServices/default', 'name': 'default'}],
    })
    blob_service = {'resource_group_name': 'rg', 'storage_account_name': 'sa'}
    account = {'resourceGroup': 'rg', 'name': 'sa'}

    with patch.object(storage, 'get_client', return_value=client):
        [container] = storage.get_blob_containers(MagicMock(), '00-00', blob_service)
        [queue_service] = storage.get_queue_services(MagicMock(), '00-00', account)

    assert container['public_access'] == 'Container'
    assert queue_service['id'] == f'{SA_ID}/queueServices/default'
