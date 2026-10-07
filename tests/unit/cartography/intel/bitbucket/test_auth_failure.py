from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch

from requests.exceptions import RequestException

from cartography.cli import _sync_response
from cartography.intel.bitbucket import repositories
from cartography.intel.bitbucket import start_bitbucket_ingestion


def _config(token="token"):
    return SimpleNamespace(
        bitbucket_access_token=token,
        update_tag=1791289020,
        params={"workspace": {"id_string": "b7aa4280", "account_id": "mobilewaretech"}},
    )


def test_missing_token_does_not_clean_or_look_like_a_snapshot():
    with patch("cartography.intel.bitbucket.run_cleanup_job") as cleanup:
        result = start_bitbucket_ingestion(Mock(), _config(token=None))

    cleanup.assert_not_called()
    assert result["authFailed"] is True
    published = _sync_response(result)
    assert published["status"] == "failure"
    assert published["authFailed"] is True
    assert published["updateTag"] is None


def test_inaccessible_workspace_does_not_clean_the_graph():
    with patch("cartography.intel.bitbucket.workspace.get_workspaces", return_value=[]), patch(
        "cartography.intel.bitbucket.workspace.get_workspace",
        return_value=None,
    ), patch("cartography.intel.bitbucket.run_cleanup_job") as cleanup:
        result = start_bitbucket_ingestion(Mock(), _config())

    cleanup.assert_not_called()
    assert result["authFailed"] is True


def test_bitbucket_request_error_does_not_return_a_successful_update_tag():
    with patch(
        "cartography.intel.bitbucket.workspace.get_workspaces",
        side_effect=RequestException("401"),
    ), patch("cartography.intel.bitbucket.run_cleanup_job") as cleanup:
        result = start_bitbucket_ingestion(Mock(), _config())

    cleanup.assert_not_called()
    assert result["authFailed"] is True
    assert "UPDATE_TAG" not in result


def test_unreadable_repository_list_does_not_sync_or_clean_the_workspace():
    workspace = {"slug": "mobilewaretech", "uuid": "ws-uuid"}
    with patch("cartography.intel.bitbucket.workspace.get_workspaces", return_value=[workspace]), patch(
        "cartography.intel.bitbucket.workspace.sync",
    ), patch(
        "cartography.intel.bitbucket.repositories.make_requests_url",
        return_value=({}, 401),
    ), patch.dict(
        "cartography.intel.bitbucket.RESOURCE_FUNCTIONS",
        {"members": Mock(), "projects": Mock(), "repositories": Mock()},
        clear=True,
    ) as services, patch("cartography.intel.bitbucket.run_cleanup_job") as cleanup:
        result = start_bitbucket_ingestion(Mock(), _config())

    for service in services.values():
        service.assert_not_called()
    cleanup.assert_not_called()
    assert result["authFailed"] is True


def test_later_repository_page_failure_keeps_repositories_already_read():
    pages = [
        ({"values": [{"slug": "repo-1"}], "next": "page-2"}, 200),
        ({}, 401),
    ]
    with patch("cartography.intel.bitbucket.repositories.make_requests_url", side_effect=pages):
        repos, list_complete = repositories.get_repos("token", "mobilewaretech")

    assert repos == [{"slug": "repo-1"}]
    assert list_complete is False


def test_empty_repository_list_is_a_completed_read():
    with patch(
        "cartography.intel.bitbucket.repositories.make_requests_url",
        return_value=({"values": []}, 200),
    ):
        repos, list_complete = repositories.get_repos("token", "mobilewaretech")

    assert repos == []
    assert list_complete is True


def test_completed_sync_result_is_still_a_success_snapshot():
    published = _sync_response({"UPDATE_TAG": 1791289020, "pagination": None})

    assert published["status"] == "success"
    assert published["updateTag"] == 1791289020
    assert "authFailed" not in published
