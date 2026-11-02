from cartography.intel.azure import function_app
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

APP_A = arm_id(SUB_A, 'Microsoft.Web/sites/app')
APP_B = arm_id(SUB_B, 'Microsoft.Web/sites/app')
# An id the API returned while syncing SUB_A that names SUB_B: its subscription segment is not an anchor.
APP_FOREIGN = arm_id(SUB_B, 'Microsoft.Web/sites/app-foreign')
# (loader, child label, path segment under the app)
CHILDREN = [
    (function_app.load_function_apps_configurations, 'AzureFunctionAppConfiguration', 'config'),
    (function_app.load_function_apps_functions, 'AzureFunctionAppFunction', 'functions'),
    (function_app.load_function_apps_deployments, 'AzureFunctionAppDeployment', 'deployments'),
    (function_app.load_function_apps_backups, 'AzureFunctionAppBackup', 'backups'),
    (function_app.load_function_apps_processes, 'AzureFunctionAppProcess', 'processes'),
    (function_app.load_function_apps_snapshots, 'AzureFunctionAppSnapshot', 'snapshots'),
    (function_app.load_function_apps_webjobs, 'AzureFunctionAppWebJob', 'webjobs'),
]


def _load_apps(neo4j_session):
    seed_customers(neo4j_session)
    seed_node(neo4j_session, SUB_B, 'AzureFunctionApp', APP_B)
    function_app.load_function_apps(
        neo4j_session, SUB_A, [{'id': APP_A, 'name': 'app'}, {'id': APP_FOREIGN, 'name': 'app-foreign'}], UPDATE_TAG,
    )


def test_function_app_resource_group_is_the_syncing_subscriptions(neo4j_session):
    _load_apps(neo4j_session)

    # The syncing subscription's group of that name, never the one the id points at.
    assert resource_group_of(neo4j_session, 'AzureFunctionApp', APP_A) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureFunctionApp', APP_FOREIGN) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureFunctionApp', APP_B) == set()


def test_function_app_children_stay_in_the_syncing_subscription(neo4j_session):
    _load_apps(neo4j_session)
    for load, _, segment in CHILDREN:
        load(
            neo4j_session, SUB_A,
            [
                {'id': f'{APP_A}/{segment}/own', 'function_app_id': APP_A},
                # same child path under the other customer's app id
                {'id': f'{APP_B}/{segment}/x', 'function_app_id': APP_B},
            ],
            UPDATE_TAG,
        )

    for _, label, segment in CHILDREN:
        own, foreign = f'{APP_A}/{segment}/own', f'{APP_B}/{segment}/x'
        assert linked_ids(neo4j_session, 'AzureFunctionApp', APP_A, 'CONTAIN', label) == {own}
        assert linked_ids(neo4j_session, 'AzureFunctionApp', APP_B, 'CONTAIN', label) == set()
        assert resource_group_of(neo4j_session, label, own) == {rg_id(SUB_A)}
        # A child whose app is not in the syncing subscription gets no group from it, nor from SUB_B.
        assert resource_group_of(neo4j_session, label, foreign) == set()
