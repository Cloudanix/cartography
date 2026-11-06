"""
Every Bitbucket lookup is anchored to the syncing Cloudanix workspace (AGENTS.md "Tenant isolation"): a row naming
another workspace's Bitbucket workspace, project or repository links nothing; one of a second Bitbucket workspace
of the same Cloudanix workspace still links.
"""
import pytest

from cartography.intel.bitbucket import members
from cartography.intel.bitbucket import projects
from cartography.intel.bitbucket import repositories

TEST_UPDATE_TAG = 123456789
WS_A = 'ws-bb-a'
# (cloudanix workspace, bitbucket workspace, project, repo)
CHAINS = (
    (WS_A, 'bw-a', 'proj-a', 'repo-a'),
    (WS_A, 'bw-a2', 'proj-a2', 'repo-a2'),  # a second Bitbucket workspace of the same customer
    ('ws-bb-b', 'bw-b', 'proj-b', 'repo-b'),
)
PARAMS = {'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': WS_A}
OWN_BITBUCKET_WORKSPACES = {'bw-a', 'bw-a2'}
OWN_REPOS = {'repo-a', 'repo-a2'}


@pytest.fixture
def two_workspaces(neo4j_session):
    neo4j_session.run('MATCH (n) DETACH DELETE n')
    for ws, bw, project, repo in CHAINS:
        neo4j_session.run(
            'MERGE (w:CloudanixWorkspace{id: $ws}) MERGE (b:BitbucketWorkspace{id: $bw}) MERGE (w)-[:OWNER]->(b) '
            'MERGE (p:BitbucketProject{id: $project}) MERGE (b)-[:RESOURCE]->(p) '
            'MERGE (r:BitbucketRepository{id: $repo}) MERGE (p)-[:RESOURCE]->(r)',
            ws=ws, bw=bw, project=project, repo=repo,
        )
    yield
    neo4j_session.run('MATCH (n) DETACH DELETE n')


def _ids(neo4j_session, query):
    return {row['id'] for row in neo4j_session.run(query)}


def test_members_attach_only_to_the_workspaces_bitbucket_workspaces(neo4j_session, two_workspaces):
    members.load_members_data(
        neo4j_session,
        [{'user': {'uuid': f'user-{bw}'}, 'workspace': {'uuid': bw}} for _, bw, _, _ in CHAINS],
        PARAMS,
    )

    query = 'MATCH (b:BitbucketWorkspace)-[:MEMBER]->() RETURN b.id AS id'
    assert _ids(neo4j_session, query) == OWN_BITBUCKET_WORKSPACES


def test_projects_attach_only_to_the_workspaces_bitbucket_workspaces(neo4j_session, two_workspaces):
    projects.load_projects_data(
        neo4j_session,
        [{'uuid': f'new-{bw}', 'workspace': {'uuid': bw}, 'owner': {}} for _, bw, _, _ in CHAINS],
        PARAMS,
    )

    query = 'MATCH (b:BitbucketWorkspace)-[:RESOURCE]->(p) WHERE p.id STARTS WITH "new-" RETURN b.id AS id'
    assert _ids(neo4j_session, query) == OWN_BITBUCKET_WORKSPACES


def test_repositories_attach_only_to_the_workspaces_projects(neo4j_session, two_workspaces):
    repositories.load_repositories_data(
        neo4j_session,
        [
            {'uuid': f'new-{project}', 'project': {'uuid': project}, 'owner': {}, 'parent': {}}
            for _, _, project, _ in CHAINS
        ],
        PARAMS,
    )

    query = 'MATCH (p:BitbucketProject)-[:RESOURCE]->(r) WHERE r.id STARTS WITH "new-" RETURN p.id AS id'
    assert _ids(neo4j_session, query) == {'proj-a', 'proj-a2'}


def test_repo_children_reach_only_the_workspaces_repos(neo4j_session, two_workspaces):
    targets = [repo for _, _, _, repo in CHAINS]
    repositories.load_branches(
        neo4j_session, [{'id': f'{r}:main', 'name': 'main', 'repo_id': r} for r in targets], PARAMS,
    )
    repositories.load_languages(
        neo4j_session, TEST_UPDATE_TAG, [{'primary_language': 'python', 'repo_id': r} for r in targets], WS_A,
    )
    for repo in targets:
        repositories._update_repo_last_activity(
            neo4j_session, repo, [{'name': 'main', 'date': '2026-10-01T00:00:00+00:00'}], 'main', WS_A,
        )

    results = {
        'branch': _ids(neo4j_session, 'MATCH (r:BitbucketRepository)-[:BRANCH]->() RETURN r.id AS id'),
        'language': _ids(neo4j_session, 'MATCH (r:BitbucketRepository)-[:PRIMARY_LANGUAGE]->() RETURN r.id AS id'),
        'last_activity': _ids(
            neo4j_session, 'MATCH (r:BitbucketRepository) WHERE r.last_activity_at IS NOT NULL RETURN r.id AS id',
        ),
    }
    assert results == {'branch': OWN_REPOS, 'language': OWN_REPOS, 'last_activity': OWN_REPOS}
