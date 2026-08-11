"""
Unit tests for uniform neo4j interactions in the github intel modules
(perf plan Phase 3 items 5+6): writes go through load_graph_data /
run_write_query, never raw session.run.
"""
from unittest.mock import MagicMock

from cartography.intel.github import organization
from cartography.intel.github import repos
from cartography.intel.github import users

TEST_UPDATE_TAG = 123456789
COMMON_JOB_PARAMS = {"UPDATE_TAG": TEST_UPDATE_TAG, "WORKSPACE_ID": "ws-1"}

ORG_DATA = {
    "login": "acme", "url": "https://github.com/acme", "email": None, "id": "O1",
    "name": "Acme", "description": "", "createdAt": "2020-01-01", "isVerified": True,
    "location": "", "websiteUrl": "", "requiresTwoFactorAuthentication": True,
}


class TestLoadOrganization:
    def test_write_goes_through_managed_tx(self):
        session = MagicMock()

        organization.load_organization(session, ORG_DATA, COMMON_JOB_PARAMS)

        session.run.assert_not_called()
        session.execute_write.assert_called_once()


class TestLoadOrganizationUsers:
    def test_users_batched_via_dictlist(self):
        session = MagicMock()
        user_data = [{"node": {"url": "https://github.com/u1", "login": "u1"}, "role": "MEMBER"}]

        users.load_organization_users(session, user_data, ORG_DATA, COMMON_JOB_PARAMS)

        session.run.assert_not_called()
        call = session.execute_write.call_args
        assert "UNWIND $DictList" in call.args[1]
        assert call.kwargs["DictList"] == user_data
        assert call.kwargs["workspace_id"] == "ws-1"


class TestReposLoaders:
    def test_repos_languages_branches_requirements_batched(self):
        session = MagicMock()
        repos.load_github_repos(session, TEST_UPDATE_TAG, [{"id": "r1"}])
        repos.load_github_languages(session, TEST_UPDATE_TAG, [{"language_name": "python", "repo_id": "r1"}])
        repos.load_github_branches(session, TEST_UPDATE_TAG, [{"id": "b1", "repo_id": "r1"}])
        repos.load_python_requirements(session, TEST_UPDATE_TAG, [{"id": "req|1", "name": "req"}])

        session.run.assert_not_called()
        assert session.execute_write.call_count == 4
        for call in session.execute_write.call_args_list:
            assert "UNWIND $DictList" in call.args[1]
            assert len(call.kwargs["DictList"]) == 1

    def test_collaborators_batched_per_type(self):
        session = MagicMock()
        collaborators = {
            "WRITE": [{"url": "https://github.com/u1", "repo_url": "r1"}],
            "READ": [{"url": "https://github.com/u2", "repo_url": "r1"}],
        }

        repos.load_collaborators(session, TEST_UPDATE_TAG, collaborators)

        session.run.assert_not_called()
        assert session.execute_write.call_count == 2
        queries = [c.args[1] for c in session.execute_write.call_args_list]
        assert any("OUTSIDE_COLLAB_WRITE" in q for q in queries)
        assert any("OUTSIDE_COLLAB_READ" in q for q in queries)
        assert all("UNWIND $DictList" in q for q in queries)
