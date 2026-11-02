from cartography.intel.azure import containerregistry
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import CUSTOMERS
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

REGISTRY_A = arm_id(SUB_A, 'Microsoft.ContainerRegistry/registries/acr')
REGISTRY_B = arm_id(SUB_B, 'Microsoft.ContainerRegistry/registries/acr')
REPO_A, REPO_B = f'{REGISTRY_A}/repositories/web', f'{REGISTRY_B}/repositories/web'
LABELS = ('AzureContainerRepository', 'AzureContainerImage')


def _params(sub, workspace_and_tenant):
    workspace_id, tenant_id = workspace_and_tenant
    return {
        'UPDATE_TAG': UPDATE_TAG + 1, 'WORKSPACE_ID': workspace_id, 'AZURE_TENANT_ID': tenant_id,
        'AZURE_SUBSCRIPTION_ID': sub, 'LIMIT_SIZE': 1000,
    }


def test_registry_contents_link_only_under_the_syncing_subscription(neo4j_session):
    seed_customers(neo4j_session)
    seed_node(neo4j_session, SUB_B, 'AzureContainerRegistry', REGISTRY_B)
    neo4j_session.run(
        "MATCH (:AzureSubscription{id: $sub})-[:RESOURCE]->(reg:AzureContainerRegistry{id: $reg}) "
        "MERGE (reg)-[:CONTAIN]->(:AzureContainerRepository{id: $repo})",
        sub=SUB_B, reg=REGISTRY_B, repo=REPO_B,
    )
    containerregistry.load_registries(neo4j_session, SUB_A, [{'id': REGISTRY_A}], UPDATE_TAG)

    containerregistry.load_repositories(
        neo4j_session, SUB_A,
        [{'id': REPO_A, 'registry_id': REGISTRY_A}, {'id': f'{REGISTRY_B}/repositories/x', 'registry_id': REGISTRY_B}],
        UPDATE_TAG,
    )
    containerregistry.load_images(
        neo4j_session, SUB_A,
        [{'id': f'{REPO_A}@sha256:1', 'repository_id': REPO_A}, {'id': f'{REPO_B}@sha256:1', 'repository_id': REPO_B}],
        UPDATE_TAG,
    )
    containerregistry.load_registry_fetch_status(neo4j_session, SUB_A, REGISTRY_B, {'repositories_fetched': True})

    assert linked_ids(neo4j_session, 'AzureContainerRegistry', REGISTRY_A, 'CONTAIN', LABELS[0]) == {REPO_A}
    assert linked_ids(neo4j_session, 'AzureContainerRegistry', REGISTRY_B, 'CONTAIN', LABELS[0]) == {REPO_B}
    assert linked_ids(neo4j_session, 'AzureContainerRepository', REPO_A, 'CONTAIN', LABELS[1]) == {
        f'{REPO_A}@sha256:1',
    }
    assert linked_ids(neo4j_session, 'AzureContainerRepository', REPO_B, 'CONTAIN', LABELS[1]) == set()
    fetched = neo4j_session.run(
        "MATCH (r:AzureContainerRegistry{id: $id}) RETURN r.repositories_fetched AS f", id=REGISTRY_B,
    ).single()['f']
    assert fetched is None


def _seed_orphans(neo4j_session, sub):
    for label in LABELS:
        neo4j_session.run(
            f"CREATE (:{label}{{id: $id, subscription_id: $sub, lastupdated: $tag}})",
            id=f'{sub}/{label}/orphan', sub=sub, tag=UPDATE_TAG,
        )


def _orphans(neo4j_session):
    rows = neo4j_session.run(
        "MATCH (n) WHERE (n:AzureContainerRepository OR n:AzureContainerImage) AND n.id ENDS WITH '/orphan' "
        "RETURN n.id AS id",
    )
    return {row['id'] for row in rows}


def test_orphan_sweeps_run_only_from_the_subscriptions_own_tenant(neo4j_session):
    seed_customers(neo4j_session)
    for sub in (SUB_A, SUB_B):
        _seed_orphans(neo4j_session, sub)
    expected_b = {f'{SUB_B}/{label}/orphan' for label in LABELS}

    # A run whose workspace / tenant does not own SUB_A deletes nothing of SUB_A's.
    foreign = _params(SUB_A, CUSTOMERS[SUB_B])
    containerregistry.cleanup_container_images(neo4j_session, foreign)
    containerregistry.cleanup_container_repositories(neo4j_session, foreign)
    assert _orphans(neo4j_session) == {f'{SUB_A}/{label}/orphan' for label in LABELS} | expected_b

    # SUB_A's own sync sweeps its own orphans and never SUB_B's.
    own = _params(SUB_A, CUSTOMERS[SUB_A])
    containerregistry.cleanup_container_images(neo4j_session, own)
    containerregistry.cleanup_container_repositories(neo4j_session, own)
    assert _orphans(neo4j_session) == expected_b
