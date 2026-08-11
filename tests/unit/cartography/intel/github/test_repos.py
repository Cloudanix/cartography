from unittest.mock import Mock
from unittest.mock import patch

from cartography.intel.github import repos


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
