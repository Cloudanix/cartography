from cartography.intel.gitlab import projects

TEST_UPDATE_TAG = 123456789
WORKSPACE_ID = 'ws-gitlab'
GROUP = 'platform'


def _seed_group(neo4j_session, workspace_id, group_node_id):
    neo4j_session.run(
        """
        MERGE (w:CloudanixWorkspace{id: $workspace_id})
        MERGE (w)-[:OWNER]->(:GitLabGroup{id: $group_node_id})
        """,
        workspace_id=workspace_id, group_node_id=group_node_id,
    )


def _project(project_id, path):
    return {
        'id': project_id,
        'path': path,
        'name': path,
        'path_with_namespace': f'{GROUP}/{path}',
        'namespace': {'path': GROUP},
        'visibility': 'private',
        'web_url': f'https://gitlab.com/{GROUP}/{path}',
    }


def test_project_sync_is_idempotent(neo4j_session):
    # The loader used to MERGE on the path and then overwrite id with the numeric id, so the next sync's
    # MERGE never found the node again and created a duplicate project each run.
    _seed_group(neo4j_session, WORKSPACE_ID, GROUP)
    data = [_project(1001, 'api'), _project(1002, 'web')]
    common_job_parameters = {'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': WORKSPACE_ID}

    projects.load_projects_data(neo4j_session, data, common_job_parameters, GROUP)
    projects.load_projects_data(
        neo4j_session, data, {**common_job_parameters, 'UPDATE_TAG': TEST_UPDATE_TAG + 1}, GROUP,
    )

    rows = neo4j_session.run(
        """
        MATCH (:GitLabGroup{id: $group})-[:RESOURCE]->(p:GitLabProject)
        RETURN p.id AS id, p.lastupdated AS lastupdated
        """,
        group=GROUP,
    )
    assert sorted((row['id'], row['lastupdated']) for row in rows) == [
        (1001, TEST_UPDATE_TAG + 1), (1002, TEST_UPDATE_TAG + 1),
    ]
