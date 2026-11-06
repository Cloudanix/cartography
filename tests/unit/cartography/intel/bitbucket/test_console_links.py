from cartography.intel.bitbucket import members
from cartography.intel.bitbucket import projects
from cartography.intel.bitbucket import repositories
from cartography.intel.bitbucket import workspace


def _uuid(value: str) -> str:
    return "{" + value + "}"


def test_transforms_set_console_links() -> None:
    ws = workspace.transform_workspaces([{"uuid": _uuid("w1"), "slug": "acme"}])[0]
    assert ws["consolelink"] == "https://bitbucket.org/acme"

    project = projects.transform_projects(
        [{"uuid": _uuid("p1"), "key": "PLAT", "workspace": {"uuid": _uuid("w1")}}], "acme",
    )[0]
    assert project["consolelink"] == "https://bitbucket.org/acme/workspace/projects/PLAT"

    repo = repositories.transform_repos(
        [{
            "uuid": _uuid("r1"), "slug": "api", "workspace": {"uuid": _uuid("w1")},
            "project": {"uuid": _uuid("p1"), "key": "PLAT"},
        }],
        "acme",
    )["repos"][0]
    assert repo["consolelink"] == "https://bitbucket.org/acme/api"

    branch = repositories.transform_branches([{"name": "main"}], "r1", "main", "acme", "api")[0]
    assert branch["consolelink"] == "https://bitbucket.org/acme/api/src/main"

    member = members.transform_members(
        [{"workspace": {"uuid": _uuid("w1")}, "user": {"uuid": _uuid("u1"), "nickname": "alice"}}], "acme",
    )[0]
    assert member["consolelink"] == "https://bitbucket.org/acme/workspace/settings/user-directory"


def test_branch_without_repo_slug_has_no_console_link() -> None:
    assert repositories.transform_branches([{"name": "main"}], "r1", "main")[0]["consolelink"] is None
