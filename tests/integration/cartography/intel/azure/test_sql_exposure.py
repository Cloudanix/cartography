"""
Scenario test for azure_sql_asset_exposure.json, run for real on Neo4j with
servers and firewall rules loaded through the sql.py loaders.
"""
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
    servers = [closed, open_all, azure_services, office_ip, wide, slash8, unknown_access, no_rules, flexible, stale]
    sql.load_server_data(neo4j_session, SUB, servers, 1)
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
    }
