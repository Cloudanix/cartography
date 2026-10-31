from typing import Dict
from typing import List
from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.azure import containerregistry
from tests.data.azure.containerregistry import MANIFESTS

WORKSPACE = 'acr-ws'
TENANT = 'acr-tenant'
SUB = 'acr-sub'
OTHER_SUB = 'acr-other-sub'
REGISTRY_ID = f'/subscriptions/{SUB}/resourceGroups/rg-acr/providers/Microsoft.ContainerRegistry/registries/acrreg'
OTHER_REGISTRY_ID = (
    f'/subscriptions/{OTHER_SUB}/resourceGroups/rg/providers/Microsoft.ContainerRegistry/registries/otherreg'
)
WEBAPP_ID = f'{REGISTRY_ID}/repositories/webapp'
API_ID = f'{REGISTRY_ID}/repositories/api-service'

# The path inventory-sync-aws walks from the subscription (config/inventory.azure.json).
INVENTORY_PATHS = {
    'AzureContainerRepository': '-[r1:RESOURCE]->(a1:AzureContainerRegistry)-[r2:CONTAIN]->',
    'AzureContainerImage': (
        '-[r1:RESOURCE]->(a1:AzureContainerRegistry)-[r2:CONTAIN]->(a2:AzureContainerRepository)-[r3:CONTAIN]->'
    ),
}


def _registry(registry_id: str = REGISTRY_ID, subscription_id: str = SUB) -> Dict:
    return {
        'id': registry_id, 'name': registry_id.rsplit('/', 1)[-1], 'location': 'eastus', 'resource_group': 'rg-acr',
        'login_server': f"{registry_id.rsplit('/', 1)[-1]}.azurecr.io", 'public_network_access': 'Enabled',
        'subscription_id': subscription_id, 'console_link': 'https://portal.azure.com/x',
    }


def _params(update_tag: int, subscription_id: str = SUB) -> Dict:
    return {
        'UPDATE_TAG': update_tag, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
        'AZURE_SUBSCRIPTION_ID': subscription_id, 'LIMIT_SIZE': 1000,
    }


def _seed_chain(neo4j_session, subscription_id: str = SUB) -> None:
    neo4j_session.run(
        "MERGE (w:CloudanixWorkspace{id: $ws})-[:OWNER]->(t:AzureTenant{id: $tenant}) "
        "MERGE (t)-[:RESOURCE]->(:AzureSubscription{id: $sub})",
        ws=WORKSPACE, tenant=TENANT, sub=subscription_id,
    )


def _client(repository_names: List[str]) -> MagicMock:
    client = MagicMock()
    client.list_repository_names.side_effect = lambda **kwargs: iter(repository_names)
    client.list_manifest_properties.side_effect = lambda name, **kwargs: iter(MANIFESTS)
    return client


def _sync_registry(neo4j_session, registry: Dict, repository_names: List[str], update_tag: int) -> None:
    containerregistry.load_registries(neo4j_session, registry['subscription_id'], [registry], update_tag)
    with patch.object(containerregistry, 'get_registry_client', return_value=_client(repository_names)):
        containerregistry.sync_registry_contents(neo4j_session, MagicMock(), registry, update_tag)


def _ids_on_inventory_path(neo4j_session, label: str, subscription_id: str = SUB) -> set:
    query = f"MATCH (:AzureSubscription{{id: $sub}}){INVENTORY_PATHS[label]}(n:{label}) RETURN n.id AS id"
    return {r['id'] for r in neo4j_session.run(query, sub=subscription_id)}


def test_repositories_and_images_have_stable_ids_on_the_inventory_path(neo4j_session):
    _seed_chain(neo4j_session)

    _sync_registry(neo4j_session, _registry(), ['webapp', 'api-service'], 1)
    _sync_registry(neo4j_session, _registry(), ['webapp', 'api-service'], 2)

    assert _ids_on_inventory_path(neo4j_session, 'AzureContainerRepository') == {WEBAPP_ID, API_ID}
    assert _ids_on_inventory_path(neo4j_session, 'AzureContainerImage') == {
        f'{repo}@{m.digest}' for repo in (WEBAPP_ID, API_ID) for m in MANIFESTS
    }
    repo = neo4j_session.run(
        "MATCH (r:AzureContainerRepository{id: $id}) RETURN r", id=WEBAPP_ID,
    ).single()['r']
    assert (repo['name'], repo['region'], repo['resourcegroup']) == ('webapp', 'eastus', 'rg-acr')
    assert repo['lastupdated'] == 2
    assert (repo['last_update_time'], repo['manifests_truncated']) == ('2021-10-15T16:30:00+00:00', False)
    image = neo4j_session.run(
        "MATCH (i:AzureContainerImage{id: $id}) RETURN i", id=f'{WEBAPP_ID}@sha256:abc123def456',
    ).single()['i']
    assert (image['name'], image['architecture'], image['tags']) == (
        'webapp@sha256:abc123def456', 'amd64', ['latest', 'v1.2.3', 'stable'],
    )
    registry = neo4j_session.run(
        "MATCH (r:AzureContainerRegistry{id: $id}) RETURN r", id=REGISTRY_ID,
    ).single()['r']
    assert registry['repositories_fetched'] is True
    # Re-syncing must not duplicate nodes.
    assert neo4j_session.run(
        "MATCH (n) WHERE n.id STARTS WITH $prefix RETURN count(n) AS c", prefix=f'{REGISTRY_ID}/repositories/',
    ).single()['c'] == 2 + 2 * len(MANIFESTS)


def _seed_leftovers(neo4j_session, subscription_id: str, registry_id: str) -> None:
    # An image whose repository was deleted by another job, and a repository + image in the
    # shape the pre-fix loader wrote (no id, CONTAINS from the registry).
    neo4j_session.run(
        "CREATE (:AzureContainerImage{id: $reg + '/orphan', subscription_id: $sub, lastupdated: 1}) "
        "WITH 1 AS x MATCH (reg:AzureContainerRegistry{id: $reg}) "
        "CREATE (reg)-[:CONTAINS]->(:AzureContainerRepository{name: 'legacy', registry_name: 'acrreg', "
        "subscription_id: $sub, lastupdated: 1})"
        "-[:CONTAINS]->(:AzureContainerImage{digest: 'sha256:legacy', subscription_id: $sub, lastupdated: 1})",
        sub=subscription_id, reg=registry_id,
    )


def test_cleanup_removes_stale_orphaned_and_legacy_nodes_of_this_subscription_only(neo4j_session):
    sub = 'acr-sub-clean'
    registry = _registry(REGISTRY_ID.replace(SUB, sub), sub)
    _seed_chain(neo4j_session, sub)
    _seed_chain(neo4j_session, OTHER_SUB)
    _sync_registry(neo4j_session, registry, ['webapp', 'api-service'], 1)
    _sync_registry(neo4j_session, _registry(OTHER_REGISTRY_ID, OTHER_SUB), ['webapp'], 1)
    _seed_leftovers(neo4j_session, sub, registry['id'])

    _sync_registry(neo4j_session, registry, ['webapp'], 2)
    containerregistry.cleanup_container_images(neo4j_session, _params(2, sub))
    containerregistry.cleanup_container_repositories(neo4j_session, _params(2, sub))

    assert _ids_on_inventory_path(neo4j_session, 'AzureContainerRepository', sub) == {
        f"{registry['id']}/repositories/webapp",
    }
    assert neo4j_session.run(
        "MATCH (n) WHERE (n:AzureContainerRepository OR n:AzureContainerImage) AND n.subscription_id = $sub "
        "RETURN count(n) AS c", sub=sub,
    ).single()['c'] == 1 + len(MANIFESTS)
    # The other subscription's nodes are stale for this sync but not ours to delete.
    assert len(_ids_on_inventory_path(neo4j_session, 'AzureContainerImage', OTHER_SUB)) == len(MANIFESTS)


def test_deleted_registry_leaves_no_orphaned_repositories_or_images(neo4j_session):
    sub = 'acr-sub-gone'
    registry = _registry(REGISTRY_ID.replace(SUB, sub), sub)
    _seed_chain(neo4j_session, sub)
    _sync_registry(neo4j_session, registry, ['webapp'], 1)

    with patch.object(containerregistry, 'get_registry_list', return_value=[]):
        containerregistry.sync(neo4j_session, MagicMock(), sub, 2, _params(2, sub))

    assert neo4j_session.run(
        "MATCH (n) WHERE (n:AzureContainerRegistry OR n:AzureContainerRepository OR n:AzureContainerImage) "
        "AND (n.id STARTS WITH $prefix OR n.subscription_id = $sub) RETURN count(n) AS c",
        prefix=registry['id'], sub=sub,
    ).single()['c'] == 0


def test_unreadable_registry_is_marked_not_fetched(neo4j_session):
    sub = 'acr-sub-private'
    registry = {**_registry(REGISTRY_ID.replace(SUB, sub), sub), 'public_network_access': 'Disabled'}
    _seed_chain(neo4j_session, sub)

    _sync_registry(neo4j_session, registry, ['webapp'], 1)

    node = neo4j_session.run(
        "MATCH (r:AzureContainerRegistry{id: $id}) RETURN r", id=registry['id'],
    ).single()['r']
    assert node['repositories_fetched'] is False
    assert node['repositories_fetch_error'] == 'public_network_access_disabled'
    assert node['lastupdated'] == 1
