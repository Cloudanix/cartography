from cartography.intel.azure import aks
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

# Same ids in both customers' subscriptions; *_FOREIGN ids name SUB_B but come from SUB_A's sync, so their
# subscription segment is not an anchor.
CLUSTER = 'Microsoft.ContainerService/managedClusters/aks'
REGISTRY = 'Microsoft.ContainerRegistry/registries/acr'
GROUP = 'Microsoft.ContainerInstance/containerGroups/cg'
REGISTRY_CHILDREN = [
    (aks.load_container_registry_replications, 'AzureContainerRegistryReplication', 'replications'),
    (aks.load_container_registry_runs, 'AzureContainerRegistryRun', 'runs'),
    (aks.load_container_registry_tasks, 'AzureContainerRegistryTask', 'tasks'),
    (aks.load_container_registry_webhooks, 'AzureContainerRegistryWebhook', 'webhooks'),
]


def _seed(neo4j_session):
    seed_customers(neo4j_session)
    for label, path in (
        ('AzureCluster', CLUSTER), ('AzureContainerRegistry', REGISTRY), ('AzureContainerGroup', GROUP),
    ):
        seed_node(neo4j_session, SUB_B, label, arm_id(SUB_B, path))


def test_aks_resource_groups_are_the_syncing_subscriptions(neo4j_session):
    _seed(neo4j_session)

    aks.load_aks_managed_clusters(
        neo4j_session, SUB_A, [{'id': arm_id(SUB_A, CLUSTER)}, {'id': arm_id(SUB_B, f'{CLUSTER}-foreign')}],
        UPDATE_TAG,
    )
    aks.load_container_registries(
        neo4j_session, SUB_A, [{'id': arm_id(SUB_A, REGISTRY)}, {'id': arm_id(SUB_B, f'{REGISTRY}-foreign')}],
        UPDATE_TAG,
    )
    aks.load_container_groups(
        neo4j_session, SUB_A, [{'id': arm_id(SUB_A, GROUP)}, {'id': arm_id(SUB_B, f'{GROUP}-foreign')}],
        UPDATE_TAG,
    )

    for label, path in (
        ('AzureCluster', CLUSTER), ('AzureContainerRegistry', REGISTRY), ('AzureContainerGroup', GROUP),
    ):
        assert resource_group_of(neo4j_session, label, arm_id(SUB_A, path)) == {rg_id(SUB_A)}
        assert resource_group_of(neo4j_session, label, arm_id(SUB_B, f'{path}-foreign')) == {rg_id(SUB_A)}
        assert resource_group_of(neo4j_session, label, arm_id(SUB_B, path)) == set()


def test_aks_children_stay_in_the_syncing_subscription(neo4j_session):
    _seed(neo4j_session)
    cluster_a, cluster_b = arm_id(SUB_A, CLUSTER), arm_id(SUB_B, CLUSTER)
    registry_a, registry_b = arm_id(SUB_A, REGISTRY), arm_id(SUB_B, REGISTRY)
    group_a, group_b = arm_id(SUB_A, GROUP), arm_id(SUB_B, GROUP)
    aks.load_aks_managed_clusters(neo4j_session, SUB_A, [{'id': cluster_a}], UPDATE_TAG)
    aks.load_container_registries(neo4j_session, SUB_A, [{'id': registry_a}], UPDATE_TAG)
    aks.load_container_groups(neo4j_session, SUB_A, [{'id': group_a}], UPDATE_TAG)

    # Agent pools: SUB_A's sync never attaches a pool to SUB_B's cluster of the same id.
    aks.load_aks_managed_cluster_agentpools(neo4j_session, SUB_A, cluster_a, [{'id': f'{cluster_a}/pool'}], UPDATE_TAG)
    aks.load_aks_managed_cluster_agentpools(neo4j_session, SUB_A, cluster_b, [{'id': f'{cluster_b}/pool'}], UPDATE_TAG)
    assert linked_ids(neo4j_session, 'AzureCluster', cluster_a, 'HAS', 'AzureClusterAgentPool') == {f'{cluster_a}/pool'}
    assert linked_ids(neo4j_session, 'AzureCluster', cluster_b, 'HAS', 'AzureClusterAgentPool') == set()
    # Nor writes the pool node itself: the cluster anchor comes before the MERGE.
    assert neo4j_session.run(
        'MATCH (p:AzureClusterAgentPool {id: $id}) RETURN count(p) AS n', id=f'{cluster_b}/pool',
    ).single()['n'] == 0

    for load, label, segment in REGISTRY_CHILDREN:
        own, foreign = f'{registry_a}/{segment}/own', f'{registry_b}/{segment}/x'
        load(
            neo4j_session, SUB_A,
            [{'id': own, 'container_registry_id': registry_a}, {'id': foreign, 'container_registry_id': registry_b}],
            UPDATE_TAG,
        )
        assert linked_ids(neo4j_session, 'AzureContainerRegistry', registry_a, 'CONTAIN', label) == {own}
        assert linked_ids(neo4j_session, 'AzureContainerRegistry', registry_b, 'CONTAIN', label) == set()
        assert resource_group_of(neo4j_session, label, own) == {rg_id(SUB_A)}
        assert resource_group_of(neo4j_session, label, foreign) == set()

    own, foreign = f'{group_a}/containers/c', f'{group_b}/containers/c'
    aks.load_containers(
        neo4j_session, SUB_A,
        [{'id': own, 'container_group_id': group_a}, {'id': foreign, 'container_group_id': group_b}],
        UPDATE_TAG,
    )
    assert linked_ids(neo4j_session, 'AzureContainerGroup', group_a, 'CONTAIN', 'AzureContainer') == {own}
    assert linked_ids(neo4j_session, 'AzureContainerGroup', group_b, 'CONTAIN', 'AzureContainer') == set()
    assert resource_group_of(neo4j_session, 'AzureContainer', own) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureContainer', foreign) == set()
