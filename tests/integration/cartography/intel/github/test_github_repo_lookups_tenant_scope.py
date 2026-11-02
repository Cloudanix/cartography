"""
Every repo lookup in github/repos.py is anchored to the syncing workspace (AGENTS.md "Tenant isolation"): a row
naming a repo (or an org) owned by another workspace links nothing, while a repo of another org of the same
workspace still links.
"""
import pytest

from cartography.intel.github import repos

TEST_UPDATE_TAG = 123456789
WS_A = 'ws-gh-lookup-a'
WS_B = 'ws-gh-lookup-b'
ORG_A = 'acme'
ORG_A2 = 'acme-two'  # a second org of workspace A
ORG_B = 'other'
REPO_A = 'https://github.com/acme/api'
REPO_A2 = 'https://github.com/acme-two/web'
REPO_B = 'https://github.com/other/api'


@pytest.fixture
def two_workspaces(neo4j_session):
    neo4j_session.run('MATCH (n) DETACH DELETE n')
    for ws, org, repo in ((WS_A, ORG_A, REPO_A), (WS_A, ORG_A2, REPO_A2), (WS_B, ORG_B, REPO_B)):
        neo4j_session.run(
            'MERGE (w:CloudanixWorkspace{id: $ws}) MERGE (o:GitHubOrganization{id: $org}) SET o.username = $org '
            'MERGE (w)-[:OWNER]->(o) MERGE (r:GitHubRepository{id: $repo}) MERGE (o)-[:RESOURCE]->(r)',
            ws=ws, org=org, repo=repo,
        )
    yield
    neo4j_session.run('MATCH (n) DETACH DELETE n')


def _repos_with(neo4j_session, pattern):
    return {row['id'] for row in neo4j_session.run(f'MATCH {pattern} RETURN DISTINCT repo.id AS id')}


def test_owner_rows_never_claim_through_another_workspace_org(neo4j_session, two_workspaces):
    new_repo = 'https://github.com/acme/new'
    neo4j_session.run('MERGE (:GitHubRepository{id: $id})', id=new_repo)
    rows = [
        {'type': 'Organization', 'owner': ORG_A, 'owner_node_id': ORG_A, 'repo_id': new_repo},
        # An owner id naming workspace B's org: must not attach anything to it.
        {'type': 'Organization', 'owner': 'hijacked', 'owner_node_id': ORG_B, 'repo_id': new_repo},
    ]

    repos.load_github_owners(neo4j_session, TEST_UPDATE_TAG, rows, WS_A)

    owners = {
        row['org'] for row in neo4j_session.run(
            'MATCH (o:GitHubOrganization)-[:RESOURCE]->(:GitHubRepository{id: $id}) RETURN o.id AS org', id=new_repo,
        )
    }
    assert owners == {ORG_A}
    username = neo4j_session.run('MATCH (o:GitHubOrganization{id: $id}) RETURN o.username AS u', id=ORG_B).single()
    assert username['u'] == ORG_B


def test_repo_children_link_only_to_repos_of_the_workspace(neo4j_session, two_workspaces):
    targets = (REPO_A, REPO_A2, REPO_B)
    repos.load_github_branches(
        neo4j_session, TEST_UPDATE_TAG,
        [{'branch_id': f'{r}:main', 'name': 'main', 'repo_id': r} for r in targets], WS_A,
    )
    repos.load_github_languages(
        neo4j_session, TEST_UPDATE_TAG, [{'language_name': 'Python', 'repo_id': r} for r in targets], WS_A,
    )
    repos.load_collaborators(
        neo4j_session, TEST_UPDATE_TAG,
        {'WRITE': [{'url': 'https://github.com/alice', 'login': 'alice', 'repo_url': r} for r in targets]}, WS_A,
    )
    repos.load_python_requirements(
        neo4j_session, TEST_UPDATE_TAG,
        [{'id': 'requests', 'name': 'requests', 'repo_url': r} for r in targets], WS_A,
    )

    own = {REPO_A, REPO_A2}
    assert _repos_with(neo4j_session, '(repo:GitHubRepository)-[:BRANCH]->(:GitHubBranch)') == own
    assert _repos_with(neo4j_session, '(repo:GitHubRepository)-[:LANGUAGE]->(:ProgrammingLanguage)') == own
    assert _repos_with(neo4j_session, '(repo:GitHubRepository)<-[:OUTSIDE_COLLAB_WRITE]-(:GitHubUser)') == own
    assert _repos_with(neo4j_session, '(repo:GitHubRepository)-[:REQUIRES]->(:PythonLibrary)') == own
