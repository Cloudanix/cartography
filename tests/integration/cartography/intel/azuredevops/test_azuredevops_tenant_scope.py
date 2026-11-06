import pytest

import cartography.intel.azuredevops
from cartography.config import Config
from cartography.intel.azuredevops import members
from cartography.intel.azuredevops import projects
from cartography.intel.azuredevops import repos

TEST_UPDATE_TAG = 123456789
COLLECTION = 'DefaultCollection'
# Two Azure DevOps Server instances, both with the default collection name, and one dev.azure.com organization.
TENANTS = (
    ('ws-ado-a', 'https://ado.acme.com/tfs', COLLECTION),
    ('ws-ado-b', 'https://ado.other.com/tfs', COLLECTION),
    ('ws-ado-saas', 'https://dev.azure.com', 'acme'),
)


@pytest.fixture
def three_organizations(neo4j_session, monkeypatch):
    monkeypatch.setattr(cartography.intel.azuredevops, 'get_access_token', lambda *_: 'token')
    monkeypatch.setattr(cartography.intel.azuredevops, '_organization_readable', lambda *_: True)
    monkeypatch.setattr(repos, 'get_repositories_for_project', lambda *_: [])
    for workspace_id, url, name in TENANTS:
        neo4j_session.run('MERGE (:CloudanixWorkspace{id: $id})', id=workspace_id)
        monkeypatch.setattr(
            projects, 'get_projects', lambda *_, ws=workspace_id: [{'id': f'project-{ws}', 'name': 'proj'}],
        )
        monkeypatch.setattr(members, 'get_users', lambda *_, ws=workspace_id: [{'id': f'user-{ws}'}])
        config = Config(
            neo4j_uri='bolt://unused',
            update_tag=TEST_UPDATE_TAG,
            params={'workspace': {'id_string': workspace_id, 'account_id': name}},
            azure_devops_config={
                'organization': [{'tenant_id': 't', 'client_id': 'c', 'client_secret': 's', 'url': url, 'name': name}],
            },
        )
        cartography.intel.azuredevops.start_azure_devops_ingestion(neo4j_session, config)


def _reach(neo4j_session, workspace_id, path):
    rows = neo4j_session.run(
        f'MATCH (:CloudanixWorkspace{{id: $ws}})-[:OWNER]->(o:AzureDevOpsOrganization){path} RETURN n.id AS id',
        ws=workspace_id,
    )
    return {row['id'] for row in rows}


def test_server_collections_with_the_same_name_stay_separate(neo4j_session, three_organizations):
    # dev.azure.com keeps the bare organization name; each server's collection is host-qualified.
    assert _reach(neo4j_session, 'ws-ado-a', '-[*0]->(n)') == {f'ado.acme.com/tfs/{COLLECTION}'}
    assert _reach(neo4j_session, 'ws-ado-b', '-[*0]->(n)') == {f'ado.other.com/tfs/{COLLECTION}'}
    assert _reach(neo4j_session, 'ws-ado-saas', '-[*0]->(n)') == {'acme'}
    for workspace_id, _, _ in TENANTS:
        assert _reach(neo4j_session, workspace_id, '-[:HAS_PROJECT]->(n)') == {f'project-{workspace_id}'}
        assert _reach(neo4j_session, workspace_id, '<-[:MEMBER_OF]-(n)') == {f'user-{workspace_id}'}
