"""
SQL server fetchers fed real SDK models: publicNetworkAccess must reflect the
server, not the 'Disabled' default the wrong properties read always produced.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from azure.core.exceptions import HttpResponseError
from azure.mgmt.rdbms.postgresql_flexibleservers import models as pg_flex_models
from azure.mgmt.sql import models as sql_models

from cartography.intel.azure import sql
from cartography.intel.azure.util.sdk_models import as_legacy_dict

PARAMS = {'UPDATE_TAG': 1}
SUB = '/subscriptions/00-00/resourceGroups/rg/providers'
NO_ENDPOINT = {'public_endpoint': None, 'public_ip': None, 'private_ip': None}


def _enrich(server):
    with patch.object(sql, '_extract_endpoint_info', return_value=NO_ENDPOINT):
        return sql._enrich_server_data(server, MagicMock(), '00-00', PARAMS)


def test_sql_server_public_network_access_arrives():
    client = MagicMock()
    client.servers.list.return_value = [
        sql_models.Server.deserialize({
            'id': f'{SUB}/Microsoft.Sql/servers/s1', 'name': 's1', 'location': 'eastus',
            'properties': {'publicNetworkAccess': 'Enabled'},
        }),
    ]

    with patch.object(sql, 'get_client', return_value=client):
        [server] = sql._get_sql_database_servers(MagicMock(), '00-00')

    assert _enrich(server)['publicNetworkAccess'] == 'Enabled'


def test_flexible_server_public_network_access_arrives():
    client = MagicMock()
    client.servers.list.return_value = [
        pg_flex_models.Server.deserialize({
            'id': f'{SUB}/Microsoft.DBforPostgreSQL/flexibleServers/pg1', 'name': 'pg1', 'location': 'eastus',
            'properties': {'network': {'publicNetworkAccess': 'Disabled'}},
        }),
    ]

    with patch.object(sql, 'PostgreSQLFlexibleServersManagementClient', return_value=client):
        [server] = sql._get_postgresql_flexible_servers(MagicMock(), '00-00')

    assert _enrich(server)['publicNetworkAccess'] == 'Disabled'


def test_unknown_public_network_access_is_not_reported_as_disabled():
    server = {'id': f'{SUB}/Microsoft.Sql/servers/old', 'name': 'old', 'location': 'eastus'}

    assert _enrich(server)['publicNetworkAccess'] is None


def _fw_rule(name, start, end):
    server_id = f'{SUB}/Microsoft.Sql/servers/s1'
    return {
        'id': f'{server_id}/firewallRules/{name}', 'name': name, 'type': 'Microsoft.Sql/servers/firewallRules',
        'start_ip_address': start, 'end_ip_address': end,
    }


def test_wide_firewall_range_links_only_subscription_ips():
    rules = [_fw_rule('wide', '52.0.0.0', '52.3.255.255'), _fw_rule('office', '20.0.0.4', '20.0.0.5')]
    details = [(f'{SUB}/Microsoft.Sql/servers/s1', 's1', 'rg', [], [], [], [], [], [], [], rules)]

    with patch.object(sql.network, 'get_network_client'), \
            patch.object(sql.network, 'get_public_ip_addresses_list', return_value=[{'ip_address': '52.1.0.9'}]), \
            patch.object(sql, 'sync_database_details'), \
            patch.object(sql, 'attach_firewall_rule_to_public_ip') as attach:
        sql.load_server_details(MagicMock(), MagicMock(), '00-00', details, 1, PARAMS)

    linked = sorted((call.args[1]['name'], call.args[2], call.args[4]) for call in attach.call_args_list)
    # A /14 is not expanded into 262144 per-address nodes: only the subscription's own IP in it is linked.
    assert linked == [
        ('office', '20.0.0.4', 'External'),
        ('office', '20.0.0.5', 'External'),
        ('wide', '52.1.0.9', 'Internal'),
    ]


def _server_dict(provider, name):
    return {'id': f'{SUB}/{provider}/{name}', 'name': name, 'resourceGroup': 'rg'}


@pytest.mark.parametrize(
    'provider, client_class', [
        ('Microsoft.DBforPostgreSQL/flexibleServers', 'PostgreSQLFlexibleServersManagementClient'),
        ('Microsoft.DBforPostgreSQL/servers', 'PostgreSQLManagementClient'),
        ('Microsoft.DBforMySQL/flexibleServers', 'MySQLFlexibleServersManagementClient'),
        ('Microsoft.DBforMySQL/servers', 'MySQLManagementClient'),
    ],
)
def test_postgres_and_mysql_firewall_rules_use_their_own_client(provider, client_class):
    client = MagicMock()
    client.firewall_rules.list_by_server.return_value = [
        pg_flex_models.FirewallRule.deserialize({
            'id': f'{SUB}/{provider}/db1/firewallRules/all', 'name': 'all',
            'properties': {'startIpAddress': '0.0.0.0', 'endIpAddress': '255.255.255.255'},
        }),
    ]

    with patch.object(sql, client_class, return_value=client), patch.object(sql, 'get_client') as sql_client:
        [rule] = sql.get_firewall_rules(MagicMock(), '00-00', _server_dict(provider, 'db1'))

    client.firewall_rules.list_by_server.assert_called_once_with('rg', 'db1')
    sql_client.assert_not_called()
    assert (rule['start_ip_address'], rule['end_ip_address']) == ('0.0.0.0', '255.255.255.255')


def test_firewall_rules_fetch_error_is_none_not_empty():
    client = MagicMock()
    client.firewall_rules.list_by_server.side_effect = HttpResponseError('forbidden')

    with patch.object(sql, 'PostgreSQLFlexibleServersManagementClient', return_value=client):
        rules = sql.get_firewall_rules(
            MagicMock(), '00-00', _server_dict('Microsoft.DBforPostgreSQL/flexibleServers', 'db1'),
        )

    # None means "not evaluated", which keeps the server public; [] would mean "no rules".
    assert rules is None


def test_vnet_integrated_flexible_server_is_flagged():
    vnet = pg_flex_models.Server.deserialize({
        'id': f'{SUB}/Microsoft.DBforPostgreSQL/flexibleServers/pg2', 'name': 'pg2', 'location': 'eastus',
        'properties': {
            'network': {'delegatedSubnetResourceId': f'{SUB}/Microsoft.Network/virtualNetworks/v/subnets/s'},
        },
    })
    public = pg_flex_models.Server.deserialize({
        'id': f'{SUB}/Microsoft.DBforPostgreSQL/flexibleServers/pg3', 'name': 'pg3', 'location': 'eastus',
        'properties': {'network': {'publicNetworkAccess': 'Enabled'}},
    })

    assert _enrich(as_legacy_dict(vnet))['vnetIntegrated'] is True
    assert _enrich(as_legacy_dict(public))['vnetIntegrated'] is False
