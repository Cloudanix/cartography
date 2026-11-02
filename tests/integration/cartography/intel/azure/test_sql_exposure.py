"""
Scenario test for azure_sql_asset_exposure.json, run for real on Neo4j with
servers and firewall rules loaded through the sql.py loaders.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.azure import sql
from cartography.util import run_analysis_job

SUB = 'sqlx-sub'
TENANT = 'sqlx-tenant'
WORKSPACE = 'sqlx-ws'
PARAMS = {
    'UPDATE_TAG': 2, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
PREFIX = '/subscriptions/sqlx-sub/resourceGroups/rg/providers/'


def _server(name, access='Enabled', engine='sqlserver'):
    provider = 'Microsoft.Sql/servers' if engine == 'sqlserver' else 'Microsoft.DBforPostgreSQL/flexibleServers'
    return {
        'id': f'{PREFIX}{provider}/{name}', 'name': name, 'resourceGroup': 'rg', 'location': 'eastus',
        'publicNetworkAccess': access, 'engine': engine,
    }


def _rule(server, name, start, end):
    return {
        'id': f"{server['id']}/firewallRules/{name}", 'name': name, 'location': 'eastus',
        'start_ip_address': start, 'end_ip_address': end, 'server_id': server['id'],
    }


def test_sql_server_exposure(neo4j_session):
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(:AzureSubscription{id: $sub})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB,
    )
    closed = _server('closed', access='Disabled')
    open_all = _server('open-all')
    azure_services = _server('azure-services')
    office_ip = _server('office-ip')
    wide = _server('wide')
    slash8 = _server('slash8')
    unknown_access = _server('unknown-access', access=None)
    no_rules = _server('no-rules')
    flexible = _server('flexible', engine='postgres')
    stale = _server('stale', access='Disabled')
    mssql_unread = _server('mssql-unread')
    servers = [
        closed, open_all, azure_services, office_ip, wide, slash8, unknown_access, no_rules, flexible, stale,
        mssql_unread,
    ]
    sql.load_server_data(neo4j_session, SUB, servers, 1)
    # As load_server_details records it: flexible's and mssql-unread's firewall list failed.
    unread = {flexible['id'], mssql_unread['id']}
    sql._load_firewall_rules_fetched(
        neo4j_session, [{'id': s['id'], 'fetched': s['id'] not in unread} for s in servers],
    )
    sql._load_firewall_rules(
        neo4j_session,
        [
            _rule(closed, 'all', '0.0.0.0', '255.255.255.255'),
            _rule(open_all, 'all', '0.0.0.0', '255.255.255.255'),
            _rule(azure_services, 'AllowAllWindowsAzureIps', '0.0.0.0', '0.0.0.0'),
            _rule(office_ip, 'office', '203.0.113.10', '203.0.113.10'),
            _rule(wide, 'wide', '1.0.0.0', '3.255.255.255'),
            _rule(slash8, 'corp', '10.0.0.0', '10.255.255.255'),
            _rule(unknown_access, 'all', '0.0.0.0', '255.255.255.255'),
        ],
        1,
    )
    # Left over from a previous run of the old job: exposed_internet was never reset.
    neo4j_session.run(
        "MATCH (s:AzureSQLServer{id: $id}) SET s.exposed_internet = true, s.exposed_internet_type = []",
        id=stale['id'],
    )

    run_analysis_job('azure_sql_asset_exposure.json', neo4j_session, PARAMS)

    rows = neo4j_session.run(
        "MATCH (s:AzureSQLServer) WHERE s.id STARTS WITH $prefix "
        "RETURN s.name AS name, s.exposed_internet AS exposed, s.exposed_internet_type AS types",
        prefix=PREFIX,
    )
    actual = {r['name']: (r['exposed'], sorted(r['types'] or [])) for r in rows}
    assert actual == {
        'closed': (None, []),
        'open-all': (True, ['unrestricted_firewall']),
        'azure-services': (None, ['azure_services_allowed']),
        'office-ip': (None, []),
        'wide': (True, ['unrestricted_firewall']),
        'slash8': (None, []),
        'unknown-access': (True, ['unrestricted_firewall']),
        'no-rules': (None, []),
        'flexible': (True, ['firewall_not_evaluated']),
        'stale': (None, []),
        'mssql-unread': (True, ['firewall_not_evaluated']),
    }


def test_firewall_public_ip_never_rewrites_another_subscriptions_node(neo4j_session):
    other_pip = '/subscriptions/other-sub/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/theirs'
    own_pip = f'{PREFIX}Microsoft.Network/publicIPAddresses/ours'
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(s:AzureSubscription{id: $sub}) "
        "MERGE (s)-[:RESOURCE]->(:AzurePublicIPAddress{id: $own, ipAddress: '20.0.0.9', name: 'ours', lastupdated: 1}) "
        "MERGE (:AzureSubscription{id: 'other-sub'})-[:RESOURCE]->"
        "(:AzurePublicIPAddress{id: $other, ipAddress: '20.0.0.5', name: 'theirs', lastupdated: 1})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB, own=own_pip, other=other_pip,
    )
    server = _server('fw-ip')
    sql.load_server_data(neo4j_session, SUB, [server], 2)
    rules = [
        {**_rule(server, 'external', '20.0.0.5', '20.0.0.5'), 'type': 'Microsoft.Sql/servers/firewallRules'},
        {**_rule(server, 'internal', '20.0.0.9', '20.0.0.9'), 'type': 'Microsoft.Sql/servers/firewallRules'},
    ]
    details = [(server['id'], server['name'], 'rg', [], [], [], [], [], [], [], rules)]

    with patch.object(sql.network, 'get_network_client'), \
            patch.object(sql.network, 'get_public_ip_addresses_list', return_value=[{'ip_address': '20.0.0.9'}]), \
            patch.object(sql, 'sync_database_details'):
        sql.load_server_details(neo4j_session, MagicMock(), SUB, details, 2, {})
    sql.cleanup_azure_sql_servers(neo4j_session, PARAMS)

    theirs = neo4j_session.run(
        "MATCH (ip:AzurePublicIPAddress{ipAddress: '20.0.0.5'})<-[:RESOURCE]-(:AzureSubscription{id: 'other-sub'}) "
        "RETURN ip.id AS id, ip.name AS name, EXISTS { (ip)<-[:MEMBER_PUBLIC_IP_ADDRESS]-() } AS linked",
    ).data()
    assert theirs == [{'id': other_pip, 'name': 'theirs', 'linked': False}]

    links = neo4j_session.run(
        "MATCH (fw:AzureFirewallRule)-[:MEMBER_PUBLIC_IP_ADDRESS]->(ip:AzurePublicIPAddress) "
        "WHERE fw.id STARTS WITH $server RETURN fw.name AS rule, ip.id AS ip, ip.type AS type",
        server=server['id'],
    ).data()
    assert sorted(links, key=lambda row: row['rule']) == [
        {'rule': 'external', 'ip': f'/subscriptions/{SUB}/sqlFirewallExternalIp/20.0.0.5', 'type': 'External'},
        {'rule': 'internal', 'ip': own_pip, 'type': None},
    ]


def _rdbms_server(name, provider, access='Enabled', vnet=False):
    return {
        'id': f'{PREFIX}{provider}/{name}', 'name': name, 'resourceGroup': 'rg', 'location': 'eastus',
        'publicNetworkAccess': access, 'engine': 'mysql' if 'MySQL' in provider else 'postgres',
        'vnetIntegrated': vnet,
    }


def test_postgres_mysql_exposure_from_fetched_firewall_rules(neo4j_session):
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(:AzureSubscription{id: $sub})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB,
    )
    pg_flex = 'Microsoft.DBforPostgreSQL/flexibleServers'
    mysql_single = 'Microsoft.DBforMySQL/servers'
    servers = {
        'pg-allow-all': _rdbms_server('pg-allow-all', pg_flex),
        'pg-azure-services': _rdbms_server('pg-azure-services', pg_flex),
        'pg-office': _rdbms_server('pg-office', pg_flex),
        'pg-no-rules': _rdbms_server('pg-no-rules', pg_flex),
        'pg-fetch-failed': _rdbms_server('pg-fetch-failed', pg_flex),
        'pg-disabled-failed': _rdbms_server('pg-disabled-failed', pg_flex, access='Disabled'),
        'pg-vnet': _rdbms_server('pg-vnet', pg_flex, access=None, vnet=True),
        'mysql-allow-all': _rdbms_server('mysql-allow-all', mysql_single),
        'mysql-no-rules': _rdbms_server('mysql-no-rules', mysql_single),
    }
    sql.load_server_data(neo4j_session, SUB, list(servers.values()), 2)

    def rules(name, *ranges):
        server = servers[name]
        return [
            {**_rule(server, f'r{i}', start, end), 'type': 'firewallRules'} for i, (start, end) in enumerate(ranges)
        ]

    fetched = {
        'pg-allow-all': rules('pg-allow-all', ('0.0.0.0', '255.255.255.255')),
        'pg-azure-services': rules('pg-azure-services', ('0.0.0.0', '0.0.0.0')),
        'pg-office': rules('pg-office', ('52.1.2.3', '52.1.2.3')),
        'pg-no-rules': [],
        'pg-fetch-failed': None,
        'pg-disabled-failed': None,
        'pg-vnet': None,
        'mysql-allow-all': rules('mysql-allow-all', ('0.0.0.0', '255.255.255.255')),
        'mysql-no-rules': [],
    }
    details = [
        (servers[name]['id'], name, 'rg', [], [], [], [], [], [], [], fw_rules) for name, fw_rules in fetched.items()
    ]
    with patch.object(sql.network, 'get_network_client'), \
            patch.object(sql.network, 'get_public_ip_addresses_list', return_value=[]), \
            patch.object(sql, 'sync_database_details'):
        sql.load_server_details(neo4j_session, MagicMock(), SUB, details, 2, {})

    run_analysis_job('azure_sql_asset_exposure.json', neo4j_session, PARAMS)

    rows = neo4j_session.run(
        "MATCH (s:AzureSQLServer) WHERE s.id IN $ids "
        "RETURN s.name AS name, s.exposed_internet AS exposed, s.exposed_internet_type AS types",
        ids=[server['id'] for server in servers.values()],
    )
    actual = {r['name']: (r['exposed'], sorted(r['types'] or [])) for r in rows}
    assert actual == {
        'pg-allow-all': (True, ['unrestricted_firewall']),
        # Same decision as Azure SQL: Azure services only, not the internet.
        'pg-azure-services': (None, ['azure_services_allowed']),
        'pg-office': (None, []),
        'pg-no-rules': (None, []),
        # Rules could not be read: stays public (fail-safe).
        'pg-fetch-failed': (True, ['firewall_not_evaluated']),
        'pg-disabled-failed': (None, []),
        'pg-vnet': (None, []),
        'mysql-allow-all': (True, ['unrestricted_firewall']),
        'mysql-no-rules': (None, []),
    }
