"""
The project-child loaders (repositories, dependencies) reach the GitLabProject only through the syncing group
(AGENTS.md "Tenant isolation"): another group's project with the same id gets no edge.
"""
import pytest

from cartography.intel.gitlab import dependencies
from cartography.intel.gitlab import repositories

TEST_UPDATE_TAG = 123456789
GROUP_A = 'platform'
GROUP_B = 'gitlab.other.com/platform'
PROJECT_ID = 'project-42'


@pytest.fixture
def two_groups(neo4j_session):
    neo4j_session.run('MATCH (n) DETACH DELETE n')
    # Group A has no project PROJECT_ID; group B (another workspace) does.
    for ws, group, project in (('ws-gl-a', GROUP_A, 'project-own'), ('ws-gl-b', GROUP_B, PROJECT_ID)):
        neo4j_session.run(
            'MERGE (w:CloudanixWorkspace{id: $ws})-[:OWNER]->(g:GitLabGroup{id: $group}) '
            'MERGE (g)-[:RESOURCE]->(:GitLabProject{id: $project})',
            ws=ws, group=group, project=project,
        )
    yield {'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': 'ws-gl-a', 'GITLAB_GROUP_NODE_ID': GROUP_A}
    neo4j_session.run('MATCH (n) DETACH DELETE n')


def _linked_projects(neo4j_session, pattern):
    return {row['id'] for row in neo4j_session.run(f'MATCH {pattern} RETURN p.id AS id')}


def test_repositories_link_only_to_the_syncing_groups_project(neo4j_session, two_groups):
    repo = {'name': 'README.md', 'id': 'blob-1', 'type': 'blob', 'path': 'README.md', 'mode': '100644'}

    repositories.load_repositories_data(neo4j_session, [repo], PROJECT_ID, two_groups)
    repositories.load_repositories_data(neo4j_session, [repo], 'project-own', two_groups)

    assert _linked_projects(neo4j_session, '(:GitLabRepository)-[:HAS]->(p:GitLabProject)') == {'project-own'}


def test_dependencies_link_only_to_the_syncing_groups_project(neo4j_session, two_groups):
    dependency = {'name': 'requests', 'version': '2.0', 'dependency_file_path': 'requirements.txt'}

    dependencies.load_dependencies_data(neo4j_session, [dependency], PROJECT_ID, two_groups)
    dependencies.load_dependencies_data(neo4j_session, [dependency], 'project-own', two_groups)

    assert _linked_projects(neo4j_session, '(:GitLabDependency)-[:HAS]->(p:GitLabProject)') == {'project-own'}
