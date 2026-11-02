from cartography.util import run_cleanup_job

OLD_TAG = 1
OTHER_TENANT_TAG = 2
SYNC_TAG = 3


def _ids(neo4j_session, query):
    return {row['id'] for row in neo4j_session.run(query)}


def test_gitlab_member_cleanup_keeps_a_member_another_group_still_has(neo4j_session):
    # One gitlab.com user is in two tenants' groups; tenant B synced last. Tenant A's member list dropped them.
    neo4j_session.run(
        """
        MERGE (wa:CloudanixWorkspace{id: 'ws-glm-a'})-[:OWNER]->(ga:GitLabGroup{id: 'glm-a'})
        MERGE (wb:CloudanixWorkspace{id: 'ws-glm-b'})-[:OWNER]->(gb:GitLabGroup{id: 'glm-b'})
        MERGE (m:GitLabMember{id: 'glm-alice'}) SET m.lastupdated = $other
        MERGE (ga)-[ra:MEMBER]->(m) SET ra.lastupdated = $old
        MERGE (gb)-[rb:MEMBER]->(m) SET rb.lastupdated = $other
        MERGE (gone:GitLabMember{id: 'glm-departed'}) SET gone.lastupdated = $old
        """,
        old=OLD_TAG, other=OTHER_TENANT_TAG,
    )

    run_cleanup_job(
        'gitlab_group_member_cleanup.json', neo4j_session,
        {'UPDATE_TAG': SYNC_TAG, 'WORKSPACE_ID': 'ws-glm-a', 'GITLAB_GROUP_NODE_ID': 'glm-a'},
    )
    run_cleanup_job('gitlab_members_orphan_cleanup.json', neo4j_session, {'UPDATE_TAG': SYNC_TAG})

    # Tenant A's stale edge and the member nobody links to are gone; B keeps the shared member.
    links = "MATCH (g:GitLabGroup)-[:MEMBER]->(m) WHERE g.id STARTS WITH 'glm-' RETURN g.id + '>' + m.id AS id"
    assert _ids(neo4j_session, links) == {'glm-b>glm-alice'}
    members = "MATCH (m:GitLabMember) WHERE m.id STARTS WITH 'glm-' RETURN m.id AS id"
    assert _ids(neo4j_session, members) == {'glm-alice'}
