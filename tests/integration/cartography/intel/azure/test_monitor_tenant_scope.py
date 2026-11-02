from cartography.intel.azure import monitor
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

PROFILE_A = arm_id(SUB_A, 'microsoft.insights/logprofiles/default')
PROFILE_B = arm_id(SUB_B, 'microsoft.insights/logprofiles/default')
# An id the API returned while syncing SUB_A that names SUB_B: its subscription segment is not an anchor.
PROFILE_FOREIGN = arm_id(SUB_B, 'microsoft.insights/logprofiles/foreign')


def test_log_profiles_join_only_the_syncing_subscriptions_resource_group(neo4j_session):
    seed_customers(neo4j_session)
    seed_node(neo4j_session, SUB_B, 'AzureMonitorLogProfile', PROFILE_B)

    monitor.load_monitor_log_profiles(
        neo4j_session, SUB_A, [{'id': PROFILE_A, 'name': 'default'}, {'id': PROFILE_FOREIGN, 'name': 'foreign'}],
        UPDATE_TAG,
    )

    assert resource_group_of(neo4j_session, 'AzureMonitorLogProfile', PROFILE_A) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureMonitorLogProfile', PROFILE_FOREIGN) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureMonitorLogProfile', PROFILE_B) == set()
