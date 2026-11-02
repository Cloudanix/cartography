"""
Two-customer fixture for the Azure tenant-isolation tests (AGENTS.md "Tenant isolation", rule 7).

Each customer (workspace) onboards its own tenant and subscription, and both subscriptions hold a resource group
with the same name. A loader run for SUB_A must only reach SUB_A's nodes, whatever ids or names the API data
carries.
"""
from cartography.intel.azure import subscription
from cartography.intel.azure import tag

UPDATE_TAG = 123456789
SUB_A = 'aaaaaaaa-0000-0000-0000-0000000000aa'
SUB_B = 'bbbbbbbb-0000-0000-0000-0000000000bb'
CUSTOMERS = {
    SUB_A: ('ws-scope-a', 'tenant-scope-a'),
    SUB_B: ('ws-scope-b', 'tenant-scope-b'),
}
# Azure creates "NetworkWatcherRG" in every subscription that uses Network Watcher.
RESOURCE_GROUP = 'networkwatcherrg'


def rg_id(sub: str) -> str:
    return f'/subscriptions/{sub}/resourceGroups/{RESOURCE_GROUP}'


def arm_id(sub: str, provider_path: str) -> str:
    """An ARM id in the shared resource group of `sub`, e.g. arm_id(SUB_A, 'Microsoft.Sql/servers/s1')."""
    return f'{rg_id(sub)}/providers/{provider_path}'


def seed_customers(neo4j_session) -> None:
    """Workspace -> tenant -> subscription -> resource group, for both customers."""
    for sub, (workspace_id, tenant_id) in CUSTOMERS.items():
        neo4j_session.run(
            "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})",
            ws=workspace_id, tenant=tenant_id,
        )
        subscription.load_azure_subscriptions(
            neo4j_session, tenant_id, [{'id': f'/subscriptions/{sub}', 'subscriptionId': sub}], UPDATE_TAG,
        )
        tag.load_resource_groups(neo4j_session, sub, [{'id': rg_id(sub), 'name': RESOURCE_GROUP}], UPDATE_TAG)


def seed_node(neo4j_session, sub: str, label: str, node_id: str, parent_label: str = '', parent_id: str = '') -> None:
    """A node of `label` owned by `sub`: RESOURCE from the subscription, or from a parent it already owns."""
    if not parent_label:
        neo4j_session.run(
            f"MATCH (s:AzureSubscription{{id: $sub}}) MERGE (s)-[:RESOURCE]->(:{label}{{id: $id}})",
            sub=sub, id=node_id,
        )
        return
    neo4j_session.run(
        f"MATCH (:AzureSubscription{{id: $sub}})-[:RESOURCE*1..3]->(p:{parent_label}{{id: $parent}}) "
        f"MERGE (p)-[:RESOURCE]->(:{label}{{id: $id}})",
        sub=sub, parent=parent_id, id=node_id,
    )


def linked_ids(neo4j_session, start_label: str, start_id: str, rel: str, end_label: str) -> set:
    """Ids of the `end_label` nodes `start_id` links to over `rel` (either direction)."""
    rows = neo4j_session.run(
        f"MATCH (:{start_label}{{id: $id}})-[:{rel}]-(n:{end_label}) RETURN n.id AS id", id=start_id,
    )
    return {row['id'] for row in rows}


def resource_group_of(neo4j_session, label: str, node_id: str) -> set:
    return linked_ids(neo4j_session, label, node_id, 'RESOURCE_GROUP', 'AzureResourceGroup')
