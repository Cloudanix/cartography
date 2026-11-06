from cartography.util import run_cleanup_job

TENANT_ID = 'tenant-shared-sub'
SUBSCRIPTION_ID = 'cccccccc-0000-0000-0000-00000000sub1'
STALE_SUBSCRIPTION_ID = 'cccccccc-0000-0000-0000-00000000sub2'
EARLIER_SYNC_TAG = 100
LATER_SYNC_TAG = 200


def _params(subscription_id):
    return {
        'UPDATE_TAG': EARLIER_SYNC_TAG,
        'WORKSPACE_ID': 'ws-sub-1',
        'AZURE_TENANT_ID': TENANT_ID,
        'AZURE_SUBSCRIPTION_ID': subscription_id,
    }


def test_subscription_cleanup_keeps_a_subscription_another_workspace_refreshed_later(neo4j_session):
    # One subscription onboarded in two workspaces: both own the same tenant and subscription nodes.
    # Workspace 2's sync (tag 200) refreshed them after workspace 1's sync (tag 100) loaded them.
    neo4j_session.run(
        """
        MERGE (t:AzureTenant{id: $tenant})
        MERGE (:CloudanixWorkspace{id: 'ws-sub-1'})-[:OWNER]->(t)
        MERGE (:CloudanixWorkspace{id: 'ws-sub-2'})-[:OWNER]->(t)
        MERGE (t)-[r:RESOURCE]->(s:AzureSubscription{id: $sub})
        SET r.lastupdated = $later, s.lastupdated = $later
        MERGE (t)-[r2:RESOURCE]->(stale:AzureSubscription{id: $stale})
        SET r2.lastupdated = 50, stale.lastupdated = 50
        """,
        tenant=TENANT_ID, sub=SUBSCRIPTION_ID, stale=STALE_SUBSCRIPTION_ID, later=LATER_SYNC_TAG,
    )

    # Workspace 1's cleanup runs last, with its older tag.
    run_cleanup_job('azure_subscriptions_cleanup.json', neo4j_session, _params(SUBSCRIPTION_ID))
    run_cleanup_job('azure_subscriptions_cleanup.json', neo4j_session, _params(STALE_SUBSCRIPTION_ID))

    rows = neo4j_session.run(
        "MATCH (:AzureTenant{id: $tenant})-[:RESOURCE]->(s:AzureSubscription) RETURN s.id AS id",
        tenant=TENANT_ID,
    )
    # The newer one survives; a subscription neither workspace refreshed is still removed.
    assert {row['id'] for row in rows} == {SUBSCRIPTION_ID}
