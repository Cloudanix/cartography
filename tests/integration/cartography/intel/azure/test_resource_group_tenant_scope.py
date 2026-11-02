from cartography.intel.azure import compute
from cartography.intel.azure import network
from cartography.intel.azure import sql
from cartography.intel.azure import storage
from cartography.intel.azure import subscription
from cartography.intel.azure import tag

TEST_UPDATE_TAG = 123456789
# Two customers: each workspace onboards its own tenant and subscription.
TENANTS = {
    'aaaaaaaa-0000-0000-0000-00000000rg01': ('ws-rg-1', 'tenant-rg-1'),
    'bbbbbbbb-0000-0000-0000-00000000rg02': ('ws-rg-2', 'tenant-rg-2'),
}
# Azure creates "NetworkWatcherRG" in every subscription that uses Network Watcher.
RESOURCE_GROUP = 'NetworkWatcherRG'


def _rg_id(sub):
    return f'/subscriptions/{sub}/resourceGroups/{RESOURCE_GROUP}'


def _seed_subscription(neo4j_session, sub, workspace_id, tenant_id):
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})",
        ws=workspace_id, tenant=tenant_id,
    )
    subscription.load_azure_subscriptions(
        neo4j_session, tenant_id, [{'id': f'/subscriptions/{sub}', 'subscriptionId': sub}], TEST_UPDATE_TAG,
    )
    tag.load_resource_groups(
        neo4j_session, sub, [{'id': _rg_id(sub), 'name': RESOURCE_GROUP.lower()}], TEST_UPDATE_TAG,
    )


def _load_resources(neo4j_session, sub):
    # The API returns the group segment in any case; the loaders lowercase it.
    rg = f'/subscriptions/{sub}/resourceGroups/NETWORKWATCHERRG'
    server_id = f'{rg}/providers/Microsoft.Sql/servers/sql1'
    network.load_networks(
        neo4j_session, sub, [{'id': f'{rg}/providers/Microsoft.Network/virtualNetworks/vnet1'}], TEST_UPDATE_TAG,
    )
    sql.load_server_data(neo4j_session, sub, [{'id': server_id, 'name': 'sql1'}], TEST_UPDATE_TAG)
    sql.load_server_private_endpoint_connection(
        neo4j_session,
        [{
            'id': server_id,
            'private_endpoint_connections': [{
                'id': f'{server_id}/privateEndpointConnections/pec1',
                'properties': {'provisioning_state': 'Ready', 'private_endpoint': {'id': 'pe1'}},
            }],
        }],
        TEST_UPDATE_TAG,
    )
    compute.load_disks(
        neo4j_session, sub, [{'id': f'{rg}/providers/Microsoft.Compute/disks/disk1'}], TEST_UPDATE_TAG,
    )
    storage.load_storage_account_data(
        neo4j_session, sub, [{'id': f'{rg}/providers/Microsoft.Storage/storageAccounts/st1'}], TEST_UPDATE_TAG,
    )


def test_resources_link_only_to_their_own_subscriptions_resource_group(neo4j_session):
    for sub, (workspace_id, tenant_id) in TENANTS.items():
        _seed_subscription(neo4j_session, sub, workspace_id, tenant_id)
    for sub in TENANTS:
        _load_resources(neo4j_session, sub)

    rows = neo4j_session.run(
        """
        MATCH (x)-[:RESOURCE_GROUP]->(rg:AzureResourceGroup)
        WHERE x.id STARTS WITH '/subscriptions/aaaaaaaa-' OR x.id STARTS WITH '/subscriptions/bbbbbbbb-'
        RETURN x.id AS resource, collect(rg.id) AS groups
        """,
    )
    links = {row['resource']: set(row['groups']) for row in rows}

    # 5 resources per subscription, each linked to its own subscription's group only.
    assert len(links) == 2 * 5
    for resource, groups in links.items():
        sub = resource.split('/')[2]
        assert groups == {_rg_id(sub)}, resource
