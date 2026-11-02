import copy

import pytest

import cartography.intel.github
from cartography.intel.github import organization
from cartography.intel.github import repos
from cartography.intel.github import users
from tests.data.github.repos import GET_REPOS

TEST_UPDATE_TAG = 123456789
SAAS = ('ws-gh-saas', 'https://api.github.com/graphql', 'https://github.com')
GHES = ('ws-gh-ghes', 'https://ghe.acme.com/api/graphql', 'https://ghe.acme.com')
ORG = 'acme'


def _fake_api(monkeypatch, web):
    org = {
        'login': ORG, 'url': f'{web}/{ORG}', 'email': None, 'id': f'O_{web}', 'name': 'Acme', 'description': None,
        'createdAt': None, 'isVerified': False, 'location': None, 'websiteUrl': None,
    }
    member = {
        'hasTwoFactorEnabled': True, 'role': 'ADMIN',
        'node': {'url': f'{web}/alice', 'login': 'alice', 'name': 'Alice', 'isSiteAdmin': False},
    }
    repo = copy.deepcopy(GET_REPOS[0])
    repo.update(url=f'{web}/{ORG}/api', nameWithOwner=f'{ORG}/api', name='api', pushedAt='2026-10-01T00:00:00Z')
    repo['owner'].update(url=f'{web}/{ORG}', login=ORG)
    monkeypatch.setattr(organization, 'get_organization', lambda *_: dict(org))
    monkeypatch.setattr(users, 'get_users', lambda *_: ([copy.deepcopy(member)], {'url': org['url'], 'login': ORG}))
    monkeypatch.setattr(repos, 'get', lambda *_: [copy.deepcopy(repo)])


@pytest.fixture
def two_github_hosts(neo4j_session, monkeypatch):
    # The same org login on github.com and on a GitHub Enterprise Server, onboarded by two workspaces.
    monkeypatch.setenv('LOCAL_RUN', '1')
    monkeypatch.setattr(
        cartography.intel.github, 'RESOURCE_FUNCTIONS', {'users': users.sync, 'repos': repos.sync},
    )
    job_parameters = {}
    for workspace_id, api_url, web in (SAAS, GHES):
        neo4j_session.run('MERGE (:CloudanixWorkspace{id: $id})', id=workspace_id)
        _fake_api(monkeypatch, web)
        params = {'WORKSPACE_ID': workspace_id, 'UPDATE_TAG': TEST_UPDATE_TAG, 'ORGANIZATION_ID': ORG}
        cartography.intel.github.sync_organization(
            neo4j_session, None, {'token': 't', 'url': api_url, 'name': ORG}, params,
        )
        job_parameters[workspace_id] = params
    return job_parameters


def _reach(neo4j_session, workspace_id, path):
    rows = neo4j_session.run(
        f'MATCH (:CloudanixWorkspace{{id: $ws}})-[:OWNER]->(o:GitHubOrganization){path} RETURN n.id AS id',
        ws=workspace_id,
    )
    return {row['id'] for row in rows}


def test_org_login_on_another_host_is_a_separate_org(neo4j_session, two_github_hosts):
    orgs = neo4j_session.run(
        'MATCH (w:CloudanixWorkspace)-[:OWNER]->(o:GitHubOrganization) WHERE w.id STARTS WITH "ws-gh-" '
        'RETURN w.id AS ws, o.id AS org',
    )
    # github.com keeps the bare login; the GHES org is host-qualified.
    assert {(row['ws'], row['org']) for row in orgs} == {(SAAS[0], ORG), (GHES[0], f'ghe.acme.com/{ORG}')}
    assert two_github_hosts[SAAS[0]]['ORGANIZATION_ID'] == ORG
    assert two_github_hosts[GHES[0]]['ORGANIZATION_ID'] == f'ghe.acme.com/{ORG}'

    # Each workspace reaches only its own host's members and repos.
    assert _reach(neo4j_session, SAAS[0], '<-[:MEMBER_OF]-(n:GitHubUser)') == {'https://github.com/alice'}
    assert _reach(neo4j_session, GHES[0], '<-[:MEMBER_OF]-(n:GitHubUser)') == {'https://ghe.acme.com/alice'}
    assert _reach(neo4j_session, SAAS[0], '-[:RESOURCE]->(n:GitHubRepository)') == {'https://github.com/acme/api'}
    assert _reach(neo4j_session, GHES[0], '-[:RESOURCE]->(n:GitHubRepository)') == {'https://ghe.acme.com/acme/api'}
