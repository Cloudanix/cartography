from cartography.util import run_cleanup_job

OLD_TAG = 1
OTHER_TENANT_TAG = 2
SYNC_TAG = 3


def _ids(neo4j_session, query):
    return {row['id'] for row in neo4j_session.run(query)}


def test_azure_devops_member_cleanup_keeps_a_user_another_org_still_has(neo4j_session):
    neo4j_session.run(
        """
        MERGE (wa:CloudanixWorkspace{id: 'ws-adom-a'})-[:OWNER]->(oa:AzureDevOpsOrganization{id: 'adom-a'})
        MERGE (wb:CloudanixWorkspace{id: 'ws-adom-b'})-[:OWNER]->(ob:AzureDevOpsOrganization{id: 'adom-b'})
        MERGE (u:AzureDevOpsUser{id: 'adom-alice'}) SET u.lastupdated = $other
        MERGE (u)-[ra:MEMBER_OF]->(oa) SET ra.lastupdated = $old
        MERGE (u)-[rb:MEMBER_OF]->(ob) SET rb.lastupdated = $other
        MERGE (gone:AzureDevOpsUser{id: 'adom-departed'}) SET gone.lastupdated = $old
        """,
        old=OLD_TAG, other=OTHER_TENANT_TAG,
    )

    run_cleanup_job(
        'azure_devops_members_cleanup.json', neo4j_session,
        {'UPDATE_TAG': SYNC_TAG, 'WORKSPACE_ID': 'ws-adom-a', 'ORGANIZATION_ID': 'adom-a'},
    )
    run_cleanup_job('azure_devops_members_orphan_cleanup.json', neo4j_session, {'UPDATE_TAG': SYNC_TAG})

    # Tenant A's stale edge and the user nobody links to are gone; B keeps the shared user.
    links = (
        "MATCH (u)-[:MEMBER_OF]->(o:AzureDevOpsOrganization) WHERE o.id STARTS WITH 'adom-' "
        "RETURN u.id + '>' + o.id AS id"
    )
    assert _ids(neo4j_session, links) == {'adom-alice>adom-b'}
    users = "MATCH (u:AzureDevOpsUser) WHERE u.id STARTS WITH 'adom-' RETURN u.id AS id"
    assert _ids(neo4j_session, users) == {'adom-alice'}
