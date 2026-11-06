from typing import Optional
from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests

from cartography.intel.github import repos


# The real per-repo branch fetch, captured before the autouse fixture below stubs it out.
REAL_GET_REPO_BRANCH_REFS = repos.get_repo_branch_refs


@pytest.fixture(autouse=True)
def mock_branch_refs():
    """`get` lists each repo's branches over GraphQL; keep every test offline by default."""
    with patch("cartography.intel.github.repos.get_repo_branch_refs", return_value=None) as mock:
        yield mock


@patch("cartography.intel.github.repos.get_org_repos")
@patch("cartography.intel.github.repos.get_installation_repos")
def test_get_normalizes_repos_from_the_org_listing(
    mock_get_installation_repos: Mock,
    mock_get_org_repos: Mock,
) -> None:
    mock_get_installation_repos.return_value = None
    mock_get_org_repos.return_value = [
        {
            "name": "sample-repo",
            "full_name": "example-org/sample-repo",
            "language": "Python",
            "html_url": "https://github.com/example-org/sample-repo",
            "ssh_url": "git@github.com:example-org/sample-repo.git",
            "created_at": "2024-01-01T00:00:00Z",
            "description": "sample",
            "updated_at": "2024-01-02T00:00:00Z",
            "pushed_at": "2024-01-03T00:00:00Z",
            "homepage": "https://example.com",
            "default_branch": "main",
            "private": False,
            "archived": False,
            "disabled": False,
            "locked": False,
            "owner": {
                "login": "example-org",
                "html_url": "https://github.com/example-org",
                "type": "Organization",
            },
        },
    ]

    result = repos.get("token", "https://api.github.com/graphql", "example-org")

    assert result == [
        {
            "name": "sample-repo",
            "nameWithOwner": "example-org/sample-repo",
            "primaryLanguage": {"name": "Python"},
            "url": "https://github.com/example-org/sample-repo",
            "sshUrl": "git@github.com:example-org/sample-repo.git",
            "createdAt": "2024-01-01T00:00:00Z",
            "description": "sample",
            "updatedAt": "2024-01-02T00:00:00Z",
            "pushedAt": "2024-01-03T00:00:00Z",
            "homepageUrl": "https://example.com",
            "languages": {"totalCount": 0, "nodes": []},
            "defaultBranchRef": {"name": "main", "id": None},
            "isPrivate": False,
            "visibility": "public",
            "isArchived": False,
            "isDisabled": False,
            "isLocked": False,
            "owner": {
                "url": "https://github.com/example-org",
                "login": "example-org",
                "__typename": "Organization",
            },
            "collaborators": None,
            "requirements": None,
            "setupCfg": None,
        },
    ]
    mock_get_org_repos.assert_called_once_with("example-org", "token", "https://api.github.com/graphql")


def test_transform_accepts_raw_rest_repo_shape() -> None:
    result = repos.transform(
        [
            {
                "name": "sample-repo",
                "full_name": "example-org/sample-repo",
                "language": "Python",
                "html_url": "https://github.com/example-org/sample-repo",
                "ssh_url": "git@github.com:example-org/sample-repo.git",
                "created_at": "2024-01-01T00:00:00Z",
                "description": "sample",
                "updated_at": "2024-01-02T00:00:00Z",
                "pushed_at": "2024-01-03T00:00:00Z",
                "homepage": "https://example.com",
                "default_branch": "main",
                "private": True,
                "visibility": "private",
                "archived": False,
                "disabled": False,
                "locked": False,
                "owner": {
                    "login": "example-org",
                    "html_url": "https://github.com/example-org",
                    "type": "Organization",
                },
            },
        ],
    )

    assert result["repos"] == [
        {
            "id": "https://github.com/example-org/sample-repo",
            "createdat": "2024-01-01T00:00:00Z",
            "name": "sample-repo",
            "fullname": "example-org/sample-repo",
            "description": "sample",
            "primary_language": "python",
            "homepage": "https://example.com",
            "default_branch": "main",
            "defaultbranchid": None,
            "is_private": True,
            "visibility": "private",
            "disabled": False,
            "archived": False,
            "locked": False,
            "giturl": "git://github.com:example-org:sample-repo.git",
            "url": "https://github.com/example-org/sample-repo",
            "sshurl": "git@github.com:example-org/sample-repo.git",
            "updatedat": "2024-01-02T00:00:00Z",
            "pushedat": "2024-01-03T00:00:00Z",
            "last_activity_at": "2024-01-03T00:00:00Z",
            "last_activity_at_timestamp": 1704240000000,
        },
    ]


def test_load_github_repos_uses_is_private_field_in_query() -> None:
    neo4j_session = Mock()

    repos.load_github_repos(neo4j_session, 123, [{"id": "r1"}])

    # writes now go through load_graph_data -> execute_write(tx_fn, query, ...)
    query = neo4j_session.execute_write.call_args.args[1]
    assert "repo.is_private = repository.is_private" in query


def _rest_repo(name: str, owner_login: str = "example-org") -> dict:
    return {
        "name": name,
        "full_name": f"{owner_login}/{name}",
        "language": None,
        "html_url": f"https://github.com/{owner_login}/{name}",
        "ssh_url": f"git@github.com:{owner_login}/{name}.git",
        "created_at": "2024-01-01T00:00:00Z",
        "description": None,
        "updated_at": "2024-01-02T00:00:00Z",
        "pushed_at": "2024-01-03T00:00:00Z",
        "homepage": None,
        "default_branch": "main",
        "private": True,
        "archived": False,
        "disabled": False,
        "locked": False,
        "owner": {"login": owner_login, "html_url": f"https://github.com/{owner_login}", "type": "Organization"},
    }


@patch("cartography.intel.github.repos.get_org_repos")
@patch("cartography.intel.github.repos.get_installation_repos")
def test_get_prefers_the_installation_repo_list(
    mock_get_installation_repos: Mock,
    mock_get_org_repos: Mock,
) -> None:
    mock_get_installation_repos.return_value = [_rest_repo("granted")]

    result = repos.get("token", "https://api.github.com/graphql", "example-org")

    assert [repo["name"] for repo in result] == ["granted"]
    mock_get_org_repos.assert_not_called()


@patch("cartography.intel.github.repos.get_org_repos")
@patch("cartography.intel.github.repos.get_installation_repos")
def test_get_drops_repos_owned_by_another_account(
    mock_get_installation_repos: Mock,
    mock_get_org_repos: Mock,
) -> None:
    mock_get_installation_repos.return_value = [_rest_repo("granted"), _rest_repo("elsewhere", owner_login="other-org")]

    result = repos.get("token", "https://api.github.com/graphql", "example-org")

    assert [repo["name"] for repo in result] == ["granted"]
    mock_get_org_repos.assert_not_called()


@patch("cartography.intel.github.repos.get_org_repos")
@patch("cartography.intel.github.repos.get_installation_repos")
def test_get_falls_back_to_the_org_listing_without_an_installation_token(
    mock_get_installation_repos: Mock,
    mock_get_org_repos: Mock,
) -> None:
    mock_get_installation_repos.return_value = None
    mock_get_org_repos.return_value = [_rest_repo("from-org-listing")]

    result = repos.get("token", "https://api.github.com/graphql", "example-org")

    assert [repo["name"] for repo in result] == ["from-org-listing"]
    mock_get_org_repos.assert_called_once_with("example-org", "token", "https://api.github.com/graphql")


@patch("cartography.intel.github.repos.requests.get")
def test_get_installation_repos_returns_none_when_the_token_is_not_an_installation_token(
    mock_requests_get: Mock,
) -> None:
    mock_requests_get.return_value = Mock(status_code=403)

    assert repos.get_installation_repos("token", "https://api.github.com/graphql") is None


def _ref(name: str, committed: str = "2099-01-01T00:00:00Z") -> dict:
    return {"name": name, "id": f"ref-{name}", "target": {"committedDate": committed}}


@patch("cartography.intel.github.repos.get_installation_repos")
def test_get_links_every_branch_and_the_default_branch_id(
    mock_get_installation_repos: Mock,
    mock_branch_refs: Mock,
) -> None:
    mock_get_installation_repos.return_value = [_rest_repo("granted")]
    mock_branch_refs.return_value = {
        "defaultBranchRef": _ref("main"),
        "edges": [{"node": _ref("main")}, {"node": _ref("feature/login")}],
    }

    result = repos.transform(repos.get("token", "https://api.github.com/graphql", "example-org"))

    url = "https://github.com/example-org/granted"
    mock_branch_refs.assert_called_once_with("token", "https://api.github.com/graphql", "example-org", "granted")
    assert result["repos"][0]["defaultbranchid"] == f"{url}:ref-main"
    assert result["repos"][0]["last_activity_at"] == "2099-01-01T00:00:00Z"
    assert [(b["repo_id"], b["name"], b["branch_id"]) for b in result["branches"]] == [
        (url, "main", f"{url}:ref-main"),
        (url, "feature/login", f"{url}:ref-feature/login"),
    ]


@patch("cartography.intel.github.repos.get_installation_repos")
def test_get_keeps_a_stale_default_branch_listed(mock_get_installation_repos: Mock, mock_branch_refs: Mock) -> None:
    # Default branch outside the page set GitHub returned, and older than the 180-day window.
    mock_get_installation_repos.return_value = [_rest_repo("granted")]
    mock_branch_refs.return_value = {
        "defaultBranchRef": _ref("main", "2020-01-01T00:00:00Z"),
        "edges": [{"node": _ref("old", "2020-01-01T00:00:00Z")}],
    }

    result = repos.transform(repos.get("token", "https://api.github.com/graphql", "example-org"))

    assert [b["name"] for b in result["branches"]] == ["main"]


@patch("cartography.intel.github.repos.get_installation_repos")
def test_get_syncs_a_repo_without_branches_when_listing_fails(
    mock_get_installation_repos: Mock,
    mock_branch_refs: Mock,
) -> None:
    mock_get_installation_repos.return_value = [_rest_repo("granted"), _rest_repo("other")]
    mock_branch_refs.side_effect = [requests.exceptions.HTTPError("boom"), None]

    result = repos.get("token", "https://api.github.com/graphql", "example-org")

    assert [repo["name"] for repo in result] == ["granted", "other"]
    assert all("refs" not in repo for repo in result)
    assert result[0]["defaultBranchRef"] == {"name": "main", "id": None}


@patch("cartography.intel.github.repos.handle_rate_limit_sleep")
@patch("cartography.intel.github.repos.call_github_api")
def test_get_repo_branch_refs_follows_pagination(mock_call: Mock, mock_sleep: Mock) -> None:
    def page(names: list, has_next: bool, cursor: Optional[str] = None) -> dict:
        return {
            "data": {
                "repository": {
                    "defaultBranchRef": _ref("main"),
                    "refs": {
                        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor},
                        "edges": [{"node": _ref(n)} for n in names],
                    },
                },
            },
        }

    mock_call.side_effect = [page(["main", "a"], True, "c1"), page(["b"], False)]

    result = REAL_GET_REPO_BRANCH_REFS("token", "https://api.github.com/graphql", "example-org", "granted")

    assert result is not None
    assert [edge["node"]["name"] for edge in result["edges"]] == ["main", "a", "b"]
    assert result["defaultBranchRef"]["id"] == "ref-main"
    assert '"cursor": "c1"' in mock_call.call_args_list[1].args[1]
    mock_sleep.assert_called_once_with("token")


@patch("cartography.intel.github.repos.handle_rate_limit_sleep")
@patch("cartography.intel.github.repos.call_github_api")
def test_get_repo_branch_refs_returns_none_when_github_hides_the_repo(mock_call: Mock, mock_sleep: Mock) -> None:
    mock_call.return_value = {"data": {"repository": None}, "errors": [{"type": "NOT_FOUND"}]}

    assert REAL_GET_REPO_BRANCH_REFS("token", "https://api.github.com/graphql", "example-org", "gone") is None


@patch("cartography.intel.github.repos.requests.get")
def test_get_installation_repos_paginates_until_a_short_page(mock_requests_get: Mock) -> None:
    full_page = Mock(status_code=200)
    full_page.json.return_value = {"repositories": [_rest_repo(f"repo-{index}") for index in range(100)]}
    last_page = Mock(status_code=200)
    last_page.json.return_value = {"repositories": [_rest_repo("repo-last")]}
    mock_requests_get.side_effect = [full_page, last_page]

    result = repos.get_installation_repos("token", "https://api.github.com/graphql")

    assert result is not None
    assert len(result) == 101
    assert mock_requests_get.call_count == 2
    assert mock_requests_get.call_args_list[1].kwargs["params"]["page"] == 2
    assert mock_requests_get.call_args_list[0].args[0] == "https://api.github.com/installation/repositories"
