"""
Scenario test for azure_function_app_asset_exposure.json (App Service web and
function apps), run for real on Neo4j with sites loaded through function_app.py.
"""
from cartography.intel.azure import function_app
from cartography.util import run_analysis_job

SUB = 'webx-sub'
TENANT = 'webx-tenant'
WORKSPACE = 'webx-ws'
PARAMS = {
    'UPDATE_TAG': 2, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
PREFIX = '/subscriptions/webx-sub/resourceGroups/rg/providers/Microsoft.Web/sites/'


def _site(name, access=None, default_action=None, open_rule=None, host_names_disabled=False):
    return {
        'id': PREFIX + name, 'name': name, 'location': 'eastus', 'resource_group': 'rg',
        'hostNamesDisabled': host_names_disabled, 'publicNetworkAccess': access,
        'ipSecurityRestrictionsDefaultAction': default_action, 'openAccessRestriction': open_rule,
    }


def test_web_app_exposure(neo4j_session):
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(:AzureSubscription{id: $sub})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB,
    )
    sites = [
        _site('default', access='Enabled', default_action='Allow', open_rule=False),
        _site('unknown'),
        _site('disabled', access='Disabled'),
        _site('deny-ip-only', access='Enabled', default_action='Deny', open_rule=False),
        _site('deny-with-any', access='Enabled', default_action='Deny', open_rule=True),
        _site('deny-unknown-rules', default_action='Deny'),
        _site('host-names-disabled', access='Enabled', default_action='Allow', host_names_disabled=True),
        _site('stale', access='Disabled'),
    ]
    function_app.load_function_apps(neo4j_session, SUB, sites, 1)
    neo4j_session.run(
        "MATCH (f:AzureFunctionApp{id: $id}) "
        "SET f.exposed_internet = true, f.exposed_internet_type = ['public_endpoint']",
        id=PREFIX + 'stale',
    )

    run_analysis_job('azure_function_app_asset_exposure.json', neo4j_session, PARAMS)

    rows = neo4j_session.run(
        "MATCH (f:AzureFunctionApp) WHERE f.id STARTS WITH $prefix "
        "RETURN f.name AS name, f.exposed_internet AS exposed, f.exposed_internet_type AS types, "
        "f.publicContext IS NOT NULL AS has_context",
        prefix=PREFIX,
    )
    actual = {r['name']: (r['exposed'], r['types'], r['has_context']) for r in rows}
    public = (True, ['public_endpoint'], True)
    private = (None, None, False)
    assert actual == {
        'default': public,
        'unknown': public,
        'disabled': private,
        'deny-ip-only': private,
        'deny-with-any': public,
        'deny-unknown-rules': public,
        'host-names-disabled': private,
        'stale': private,
    }


def test_web_app_network_fields_update_on_resync(neo4j_session):
    site = _site('resync', access='Enabled', default_action='Allow', open_rule=False)
    function_app.load_function_apps(neo4j_session, SUB, [site], 1)
    function_app.load_function_apps(
        neo4j_session, SUB, [{**site, 'hostNamesDisabled': True, 'publicNetworkAccess': 'Disabled'}], 2,
    )

    row = neo4j_session.run(
        "MATCH (f:AzureFunctionApp{id: $id}) RETURN f.hostNamesDisabled AS hnd, f.publicNetworkAccess AS access",
        id=PREFIX + 'resync',
    ).single()
    assert (row['hnd'], row['access']) == (True, 'Disabled')
