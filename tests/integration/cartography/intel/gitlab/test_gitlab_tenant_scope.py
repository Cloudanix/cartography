import copy
from datetime import datetime
from datetime import timezone

import pytest

from cartography.intel.gitlab import group
from cartography.intel.gitlab import members
from cartography.intel.gitlab import projects

TEST_UPDATE_TAG = 123456789
GROUP = 'platform'
SAAS = ('ws-gl-saas', 'https://gitlab.com')
SELF_MANAGED = ('ws-gl-self', 'https://gitlab.acme.com')
PROJECT_ID = 42


def _project(project_id, path, namespace=GROUP):
    return {
        'id': project_id,
        'path': path,
        'name': path,
        'path_with_namespace': f'{namespace}/{path}',
        'namespace': {'path': namespace},
        'visibility': 'private',
        'default_branch': 'main',
    }


def test_project_sync_is_idempotent(neo4j_session):
    # The loader used to MERGE on the path and then overwrite id with the numeric id, so the next sync's
    # MERGE never found the node again and created a duplicate project each run.
    group_id = 'b2-group'
    neo4j_session.run(
        'MERGE (w:CloudanixWorkspace{id: "ws-gl-b2"}) MERGE (w)-[:OWNER]->(:GitLabGroup{id: $group_id})',
        group_id=group_id,
    )
    data = projects.transform_projects_data(
        [_project(1001, 'api', group_id), _project(1002, 'web', group_id)], 'https://gitlab.com',
    )
    common_job_parameters = {'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': 'ws-gl-b2'}

    projects.load_projects_data(neo4j_session, data, common_job_parameters, group_id)
    projects.load_projects_data(
        neo4j_session, data, {**common_job_parameters, 'UPDATE_TAG': TEST_UPDATE_TAG + 1}, group_id,
    )

    rows = neo4j_session.run(
        """
        MATCH (:GitLabGroup{id: $group_id})-[:RESOURCE]->(p:GitLabProject)
        RETURN p.id AS id, p.lastupdated AS lastupdated
        """,
        group_id=group_id,
    )
    assert sorted((row['id'], row['lastupdated']) for row in rows) == [
        (1001, TEST_UPDATE_TAG + 1), (1002, TEST_UPDATE_TAG + 1),
    ]


@pytest.fixture
def two_gitlab_instances(neo4j_session, monkeypatch):
    # The same group path, project id, project path and username on gitlab.com and on a self-managed instance,
    # onboarded by two workspaces. Paths, usernames and project ids are unique only within one instance.
    recent = datetime.now(timezone.utc).isoformat()
    monkeypatch.setattr(projects, 'get_group_projects', lambda *_: [_project(PROJECT_ID, 'api')])
    monkeypatch.setattr(projects, 'get_project_languages', lambda *_: {'Python': 100.0})
    monkeypatch.setattr(
        projects, 'get_project_branches', lambda *_: [{'name': 'main', 'commit': {'committed_date': recent}}],
    )
    monkeypatch.setattr(members, 'get_group_members', lambda *_: [{'id': 7, 'username': 'alice', 'name': 'A'}])
    for workspace_id, hosted_domain in (SAAS, SELF_MANAGED):
        neo4j_session.run('MERGE (:CloudanixWorkspace{id: $id})', id=workspace_id)
        params = {
            'WORKSPACE_ID': workspace_id,
            'UPDATE_TAG': TEST_UPDATE_TAG,
            'GITLAB_GROUP_ID': GROUP,
            # As start_gitlab_ingestion derives it from the configured host.
            'GITLAB_GROUP_NODE_ID': GROUP if hosted_domain == SAAS[1] else f'gitlab.acme.com/{GROUP}',
        }
        group.sync(
            neo4j_session, [{'id': 9, 'name': GROUP, 'full_path': GROUP}], hosted_domain, 't', copy.copy(params),
        )
        projects.sync(neo4j_session, GROUP, hosted_domain, 't', params, GROUP)
        members.sync(neo4j_session, GROUP, hosted_domain, 't', params, GROUP)


def _reach(neo4j_session, workspace_id, path):
    rows = neo4j_session.run(
        f'MATCH (:CloudanixWorkspace{{id: $ws}})-[:OWNER]->(:GitLabGroup){path} RETURN n.id AS id',
        ws=workspace_id,
    )
    return {row['id'] for row in rows}


def test_self_managed_keys_never_merge_with_gitlab_com(neo4j_session, two_gitlab_instances):
    # gitlab.com keeps its existing ids; the self-managed instance's are host-qualified.
    assert _reach(neo4j_session, SAAS[0], '-[:RESOURCE*0]->(n)') == {GROUP}
    assert _reach(neo4j_session, SELF_MANAGED[0], '-[:RESOURCE*0]->(n)') == {f'gitlab.acme.com/{GROUP}'}
    assert _reach(neo4j_session, SAAS[0], '-[:RESOURCE]->(n:GitLabProject)') == {PROJECT_ID}
    assert _reach(neo4j_session, SELF_MANAGED[0], '-[:RESOURCE]->(n:GitLabProject)') == {
        f'gitlab.acme.com/{PROJECT_ID}',
    }
    assert _reach(neo4j_session, SAAS[0], '-[:RESOURCE]->(:GitLabProject)-[:BRANCH]->(n)') == {f'{PROJECT_ID}:main'}
    assert _reach(neo4j_session, SELF_MANAGED[0], '-[:RESOURCE]->(:GitLabProject)-[:BRANCH]->(n)') == {
        f'gitlab.acme.com/{PROJECT_ID}:main',
    }
    assert _reach(neo4j_session, SAAS[0], '-[:MEMBER]->(n:GitLabMember)') == {'alice'}
    assert _reach(neo4j_session, SELF_MANAGED[0], '-[:MEMBER]->(n:GitLabMember)') == {'gitlab.acme.com/alice'}

    # No node is reachable from both workspaces.
    owners = neo4j_session.run(
        """
        MATCH (w:CloudanixWorkspace)-[:OWNER]->(:GitLabGroup)-[*0..2]->(n)
        WHERE w.id IN $workspaces
        WITH n, collect(DISTINCT w.id) AS workspaces WHERE size(workspaces) > 1
        RETURN labels(n) AS labels, n.id AS id
        """,
        workspaces=[SAAS[0], SELF_MANAGED[0]],
    )
    assert [dict(row) for row in owners] == []
