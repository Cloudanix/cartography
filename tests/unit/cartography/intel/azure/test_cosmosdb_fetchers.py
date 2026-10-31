"""
Cosmos DB account fetcher fed a real SDK model: the network fields the loader
and exposure job read must arrive.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

from azure.mgmt.cosmosdb import models

from cartography.intel.azure import cosmosdb

PARAMS = {'UPDATE_TAG': 1}
ACC_ID = '/subscriptions/00-00/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/db'


def test_database_account_network_fields_arrive():
    client = MagicMock()
    client.database_accounts.list.return_value = [
        models.DatabaseAccountGetResults({
            'id': ACC_ID, 'name': 'db', 'location': 'East US',
            'properties': {
                'publicNetworkAccess': 'Disabled',
                'isVirtualNetworkFilterEnabled': False,
                'ipRules': [{'ipAddressOrRange': '20.1.2.3'}],
                'consistencyPolicy': {'defaultConsistencyLevel': 'Session'},
            },
        }),
    ]

    with patch.object(cosmosdb, 'get_client', return_value=client):
        accounts = cosmosdb.get_database_account_list(MagicMock(), '00-00', None, PARAMS)
    [account] = cosmosdb.transform_database_account_data(accounts)

    assert account['publicNetworkAccess'] == 'Disabled'
    assert account['is_virtual_network_filter_enabled'] is False
    assert account['ipruleslist'] == ['20.1.2.3']
    assert account['consistency_policy']['default_consistency_level'] == 'Session'
    assert account['location'] == 'eastus'


def test_ip_rules_with_cidr_and_unknown_access():
    client = MagicMock()
    client.database_accounts.list.return_value = [
        models.DatabaseAccountGetResults({
            'id': ACC_ID, 'name': 'db', 'location': 'East US',
            'properties': {
                'ipRules': [
                    {'ipAddressOrRange': '52.10.0.0/24'}, {'ipAddressOrRange': '0.0.0.0'},
                    {'ipAddressOrRange': '20.1.2.3'},
                ],
            },
        }),
    ]

    with patch.object(cosmosdb, 'get_client', return_value=client):
        accounts = cosmosdb.get_database_account_list(MagicMock(), '00-00', None, PARAMS)
    [account] = cosmosdb.transform_database_account_data(accounts)

    # Unknown is not assumed Disabled: the exposure job keeps it public.
    assert account['publicNetworkAccess'] is None
    assert account['ipruleslist'] == ['52.10.0.0/24', '20.1.2.3']
    assert account['iprulecount'] == 3
