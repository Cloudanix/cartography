from cartography.util import run_cleanup_job

OLD_TAG = 1
OTHER_TENANT_TAG = 2
SYNC_TAG = 3


def _ids(neo4j_session, query):
    return {row['id'] for row in neo4j_session.run(query)}


def test_gitlab_project_cleanup_keeps_a_project_a_parent_group_still_has(neo4j_session):
    # Workspace A onboards the parent group, workspace B its subgroup; both sync the subgroup's projects
    # (projects are listed with include_subgroups). "moved" left B's subgroup but is still under A's group.
    # "dropped" is gone from both. B still has "kept", whose old branch is gone.
    neo4j_session.run(
        """
        MERGE (wa:CloudanixWorkspace{id: 'ws-glp-a'})-[:OWNER]->(ga:GitLabGroup{id: 'glp-parent'})
        MERGE (wb:CloudanixWorkspace{id: 'ws-glp-b'})-[:OWNER]->(gb:GitLabGroup{id: 'glp-parent/sub'})
        MERGE (moved:GitLabProject{id: 'glp-moved'}) SET moved.lastupdated = $other
        MERGE (moved)-[mb:BRANCH]->(movedb:GitLabBranch{id: 'glp-moved:main'})
        SET mb.lastupdated = $other, movedb.lastupdated = $other
        MERGE (ga)-[ra:RESOURCE]->(moved) SET ra.lastupdated = $other
        MERGE (gb)-[rb:RESOURCE]->(moved) SET rb.lastupdated = $old
        MERGE (dropped:GitLabProject{id: 'glp-dropped'}) SET dropped.lastupdated = $old
        MERGE (dropped)-[db:BRANCH]->(droppedb:GitLabBranch{id: 'glp-dropped:main'})
        SET db.lastupdated = $old, droppedb.lastupdated = $old
        MERGE (gb)-[rd:RESOURCE]->(dropped) SET rd.lastupdated = $old
        MERGE (kept:GitLabProject{id: 'glp-kept'}) SET kept.lastupdated = $sync
        MERGE (gb)-[rk:RESOURCE]->(kept) SET rk.lastupdated = $sync
        MERGE (kept)-[kb1:BRANCH]->(keptmain:GitLabBranch{id: 'glp-kept:main'})
        SET kb1.lastupdated = $sync, keptmain.lastupdated = $sync
        MERGE (kept)-[kb2:BRANCH]->(keptold:GitLabBranch{id: 'glp-kept:old'})
        SET kb2.lastupdated = $old, keptold.lastupdated = $old
        """,
        old=OLD_TAG, other=OTHER_TENANT_TAG, sync=SYNC_TAG,
    )

    run_cleanup_job(
        'gitlab_group_project_cleanup.json', neo4j_session,
        {'UPDATE_TAG': SYNC_TAG, 'WORKSPACE_ID': 'ws-glp-b', 'GITLAB_GROUP_NODE_ID': 'glp-parent/sub'},
    )
    run_cleanup_job('gitlab_projects_orphan_cleanup.json', neo4j_session, {'UPDATE_TAG': SYNC_TAG})

    # A keeps "moved" with its branch; B drops only its own edge to it. "dropped" (no group left) and B's
    # stale branch of "kept" are deleted.
    links = "MATCH (g:GitLabGroup)-[:RESOURCE]->(p) WHERE g.id STARTS WITH 'glp-' RETURN g.id + '>' + p.id AS id"
    assert _ids(neo4j_session, links) == {'glp-parent>glp-moved', 'glp-parent/sub>glp-kept'}
    branches = "MATCH (p:GitLabProject)-[:BRANCH]->(b) WHERE p.id STARTS WITH 'glp-' RETURN b.id AS id"
    assert _ids(neo4j_session, branches) == {'glp-moved:main', 'glp-kept:main'}
    assert _ids(
        neo4j_session,
        "MATCH (n) WHERE (n:GitLabProject OR n:GitLabBranch) AND n.id STARTS WITH 'glp-' RETURN n.id AS id",
    ) == {'glp-moved', 'glp-moved:main', 'glp-kept', 'glp-kept:main'}
