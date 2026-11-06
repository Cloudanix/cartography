"""
The Azure DevOps repo loaders reach projects and repos only through the syncing organization (AGENTS.md "Tenant
isolation"): a project or repo id of another organization (another workspace) gets no edge and no write.
"""
import pytest

from cartography.intel.azuredevops import repos

TEST_UPDATE_TAG = 123456789
# (cloudanix workspace, organization, project, repo)
CHAINS = (('ws-ado-a', 'org-a', 'p-a', 'r-a'), ('ws-ado-b', 'org-b', 'p-b', 'r-b'))
PARAMS = {'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': 'ws-ado-a', 'ORGANIZATION_ID': 'org-a'}


@pytest.fixture
def two_organizations(neo4j_session):
    neo4j_session.run('MATCH (n) DETACH DELETE n')
    for ws, org, project, repo in CHAINS:
        neo4j_session.run(
            'MERGE (w:CloudanixWorkspace{id: $ws})-[:OWNER]->(o:AzureDevOpsOrganization{id: $org}) '
            'MERGE (o)-[:HAS_PROJECT]->(p:AzureDevOpsProject{id: $project}) '
            'MERGE (p)-[:HAS_REPO]->(:AzureDevOpsRepo{id: $repo})',
            ws=ws, org=org, project=project, repo=repo,
        )
    yield
    neo4j_session.run('MATCH (n) DETACH DELETE n')


def _ids(neo4j_session, query):
    return {row['id'] for row in neo4j_session.run(query)}


def test_repositories_attach_only_to_the_organizations_projects(neo4j_session, two_organizations):
    for _, _, project, _ in CHAINS:
        repos.load_repositories(neo4j_session, [{'id': f'new-{project}', 'project': {}}], project, PARAMS)

    query = 'MATCH (p:AzureDevOpsProject)-[:HAS_REPO]->(r) WHERE r.id STARTS WITH "new-" RETURN p.id AS id'
    assert _ids(neo4j_session, query) == {'p-a'}


def test_branches_and_last_activity_reach_only_the_organizations_repos(neo4j_session, two_organizations):
    targets = [repo for _, _, _, repo in CHAINS]
    repos.load_branches_data(
        neo4j_session, [{'id': f'{r}:main', 'name': 'main', 'repo_id': r} for r in targets], PARAMS,
    )
    for repo in targets:
        repos._update_repo_last_activity(
            neo4j_session, repo, [{'name': 'main', 'commitDate': '2026-10-01T00:00:00+00:00'}], 'main', 'org-a',
        )

    results = {
        'branch': _ids(neo4j_session, 'MATCH (r:AzureDevOpsRepo)-[:BRANCH]->() RETURN r.id AS id'),
        'last_activity': _ids(
            neo4j_session, 'MATCH (r:AzureDevOpsRepo) WHERE r.last_activity_at IS NOT NULL RETURN r.id AS id',
        ),
    }
    assert results == {'branch': {'r-a'}, 'last_activity': {'r-a'}}
