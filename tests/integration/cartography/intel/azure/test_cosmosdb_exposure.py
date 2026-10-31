"""
Scenario test for azure_cosmosdb_asset_exposure.json, run for real on Neo4j
with accounts transformed and loaded through cosmosdb.py.
"""
from cartography.intel.azure import cosmosdb
from cartography.util import run_analysis_job

SUB = 'cosx-sub'
TENANT = 'cosx-tenant'
WORKSPACE = 'cosx-ws'
PARAMS = {
    'UPDATE_TAG': 2, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
PREFIX = '/subscriptions/cosx-sub/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/'


def _account(name, access='Enabled', ips=(), vnet_filter=False):
    return {
        'id': PREFIX + name, 'name': name, 'location': 'eastus', 'resourceGroup': 'rg',
        'type': 'Microsoft.DocumentDB/databaseAccounts', 'publicNetworkAccess': access,
        'is_virtual_network_filter_enabled': vnet_filter,
        'ip_rules': [{'ip_address_or_range': ip} for ip in ips],
    }


def _run(neo4j_session, accounts):
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(:AzureSubscription{id: $sub})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB,
    )
    accounts = cosmosdb.transform_database_account_data(accounts)
    cosmosdb.load_database_account_data(neo4j_session, SUB, accounts, 1)
    for account in accounts:
        cosmosdb._load_database_account_associated_iprules(neo4j_session, account, 1)

    run_analysis_job('azure_cosmosdb_asset_exposure.json', neo4j_session, PARAMS)

    rows = neo4j_session.run(
        "MATCH (a:AzureCosmosDBAccount) WHERE a.id STARTS WITH $prefix "
        "RETURN a.name AS name, a.exposed_internet AS exposed, a.exposed_internet_type AS types",
        prefix=PREFIX,
    )
    return {r['name']: (r['exposed'], sorted(r['types'] or [])) for r in rows}


def test_cosmosdb_network_exposure(neo4j_session):
    actual = _run(
        neo4j_session, [
            _account('open'),
            _account('unknown-access', access=None),
            _account('disabled', access='Disabled'),
            _account('disabled-with-ip', access='Disabled', ips=['52.1.2.3']),
            _account('vnet-only', vnet_filter=True),
            _account('datacenters-only', ips=['0.0.0.0']),
            _account('cidr', ips=['52.10.0.0/24']),
        ],
    )

    assert actual == {
        'open': (True, ['public_network']),
        'unknown-access': (True, ['public_network']),
        'disabled': (None, []),
        'disabled-with-ip': (None, []),
        'vnet-only': (None, []),
        # 0.0.0.0 admits Azure datacenters only, so the account is not open to every network.
        'datacenters-only': (None, []),
        'cidr': (True, ['public_ip']),
    }
