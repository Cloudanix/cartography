from cartography.intel.github import repos
from cartography.intel.github import teams
from cartography.intel.github import users
from cartography.intel.github.util import get_web_base_url
from cartography.intel.github.util import PaginatedGraphqlData

REPO = {
    "name": "api",
    "nameWithOwner": "acme/api",
    "primaryLanguage": None,
    "url": "https://ghe.acme.com/acme/api",
    "sshUrl": None,
    "createdAt": "2020-01-01T00:00:00Z",
    "description": None,
    "updatedAt": "2020-01-01T00:00:00Z",
    "pushedAt": "2020-01-01T00:00:00Z",
    "homepageUrl": None,
    "languages": {"totalCount": 0, "nodes": []},
    "defaultBranchRef": {"name": "main", "id": "ref1"},
    "refs": {"edges": [{"node": {"name": "main", "id": "ref1", "target": None}}]},
    "isPrivate": True,
    "isArchived": False,
    "isDisabled": False,
    "isLocked": False,
    "owner": {"url": "https://ghe.acme.com/acme", "login": "acme", "__typename": "Organization"},
    "collaborators": None,
}


def test_get_web_base_url() -> None:
    assert get_web_base_url("https://api.github.com/graphql") == "https://github.com"
    assert get_web_base_url("https://ghe.acme.com/api/graphql") == "https://ghe.acme.com"
    assert get_web_base_url("") == "https://github.com"


def test_transform_sets_repo_and_branch_console_links() -> None:
    result = repos.transform([REPO], "https://ghe.acme.com")

    assert result["repos"][0]["consolelink"] == "https://ghe.acme.com/acme/api"
    assert result["branches"][0]["consolelink"] == "https://ghe.acme.com/acme/api/tree/main"


def test_transform_users_and_teams_set_console_links() -> None:
    user_data = users.transform_users([{"node": {"login": "alice"}}, {"node": {}}], "https://github.com")
    assert user_data[0]["consolelink"] == "https://github.com/alice"
    assert user_data[1]["consolelink"] is None

    team_data = PaginatedGraphqlData(
        nodes=[{"slug": "core", "url": "u", "description": None, "repositories": {"totalCount": 0}}],
        edges=[],
    )
    result = teams.transform_teams(team_data, {"url": "o", "login": "acme"}, {"core": []}, "https://github.com")
    assert result[0]["consolelink"] == "https://github.com/orgs/acme/teams/core"
