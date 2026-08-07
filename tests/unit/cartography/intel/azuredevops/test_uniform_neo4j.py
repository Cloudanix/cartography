"""
Unit tests for uniform neo4j interactions in the azuredevops intel modules
(perf plan Phase 3 items 5+6).
"""
from unittest.mock import MagicMock

from cartography.intel.azuredevops import members
from cartography.intel.azuredevops import organization
from cartography.intel.azuredevops import projects
from cartography.intel.azuredevops import repos

COMMON_JOB_PARAMS = {"UPDATE_TAG": 123456789, "WORKSPACE_ID": "ws-1"}


class TestLoadUsers:
    def test_batched_via_dictlist(self):
        session = MagicMock()
        user_data = [{"displayName": "Alice", "principalName": "alice"}]

        members.load_users(session, user_data, "org-1", COMMON_JOB_PARAMS)

        session.run.assert_not_called()
        call = session.execute_write.call_args
        assert "UNWIND $DictList" in call.args[1]
        assert call.kwargs["DictList"] == user_data
        assert call.kwargs["OrganizationName"] == "org-1"


class TestLoadOrganization:
    def test_goes_through_managed_tx(self):
        session = MagicMock()
        org_data = {"name": "org-1", "url": "https://dev.azure.com/org-1", "status": "active"}

        organization.load_organization(session, org_data, COMMON_JOB_PARAMS)

        session.run.assert_not_called()
        session.execute_write.assert_called_once()


class TestLoadProjects:
    def test_batched_via_dictlist(self):
        session = MagicMock()
        project_data = [{"id": "p1", "name": "proj"}]

        projects.load_projects(session, project_data, "org-1", COMMON_JOB_PARAMS)

        session.run.assert_not_called()
        call = session.execute_write.call_args
        assert "UNWIND $DictList" in call.args[1]
        assert call.kwargs["DictList"] == project_data


class TestRepos:
    def test_repositories_and_branches_batched(self):
        session = MagicMock()

        repos.load_repositories(session, [{"id": "r1"}], "p1", COMMON_JOB_PARAMS)
        repos.load_branches_data(session, [{"id": "b1", "repo_id": "r1"}], COMMON_JOB_PARAMS)

        session.run.assert_not_called()
        assert session.execute_write.call_count == 2
        for call in session.execute_write.call_args_list:
            assert "UNWIND $DictList" in call.args[1]

    def test_last_activity_write_goes_through_managed_tx(self):
        session = MagicMock()
        branches = [{"name": "main", "commitDate": "2024-01-01T00:00:00+00:00"}]

        repos._update_repo_last_activity(session, "r1", branches, "main")

        session.run.assert_not_called()
        session.execute_write.assert_called_once()
