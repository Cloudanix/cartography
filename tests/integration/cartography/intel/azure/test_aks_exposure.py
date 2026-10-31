"""
Scenario test for azure_aks_asset_exposure.json, run for real on Neo4j with
clusters loaded through the aks.py loader.
"""
from cartography.intel.azure import aks
from cartography.util import run_analysis_job

SUB = 'aksx-sub'
TENANT = 'aksx-tenant'
WORKSPACE = 'aksx-ws'
PARAMS = {
    'UPDATE_TAG': 2, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
PREFIX = '/subscriptions/aksx-sub/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/'


def _cluster(name, private=None, ranges=None):
    return {
        'id': PREFIX + name, 'name': name, 'location': 'eastus', 'resource_group': 'rg',
        'publicNetworkAccess': 'Enabled', 'enablePrivateCluster': private, 'authorizedIPRanges': ranges or [],
    }


def test_aks_api_server_exposure(neo4j_session):
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(:AzureSubscription{id: $sub})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB,
    )
    clusters = [
        _cluster('default'),
        _cluster('private', private=True),
        _cluster('private-false', private=False),
        _cluster('office-only', ranges=['52.1.2.3/32', '20.0.0.0/16']),
        _cluster('open-range', ranges=['52.1.2.3/32', '0.0.0.0/0']),
        _cluster('stale', private=True),
    ]
    aks.load_aks_managed_clusters(neo4j_session, SUB, clusters, 1)
    # A cluster made private after it was first seen must not stay public.
    neo4j_session.run(
        "MATCH (c:AzureCluster{id: $id}) "
        "SET c.exposed_internet = true, c.exposed_internet_type = ['public_api_server']",
        id=PREFIX + 'stale',
    )

    run_analysis_job('azure_aks_asset_exposure.json', neo4j_session, PARAMS)

    rows = neo4j_session.run(
        "MATCH (c:AzureCluster) WHERE c.id STARTS WITH $prefix "
        "RETURN c.name AS name, c.exposed_internet AS exposed, c.exposed_internet_type AS types, "
        "c.publicContext IS NOT NULL AS has_context",
        prefix=PREFIX,
    )
    actual = {r['name']: (r['exposed'], r['types'], r['has_context']) for r in rows}
    assert actual == {
        'default': (True, ['public_api_server'], True),
        'private': (None, None, False),
        'private-false': (True, ['public_api_server'], True),
        'office-only': (None, None, False),
        'open-range': (True, ['public_api_server'], True),
        'stale': (None, None, False),
    }


def test_aks_access_profile_updates_on_resync(neo4j_session):
    cluster = _cluster('resync')
    aks.load_aks_managed_clusters(neo4j_session, SUB, [cluster], 1)
    aks.load_aks_managed_clusters(
        neo4j_session, SUB, [{**cluster, 'enablePrivateCluster': True, 'publicNetworkAccess': 'Disabled'}], 2,
    )

    row = neo4j_session.run(
        "MATCH (c:AzureCluster{id: $id}) RETURN c.enablePrivateCluster AS private, c.publicNetworkAccess AS access",
        id=PREFIX + 'resync',
    ).single()
    assert (row['private'], row['access']) == (True, 'Disabled')
