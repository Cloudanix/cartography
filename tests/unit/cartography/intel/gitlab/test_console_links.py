from cartography.intel.gitlab import group
from cartography.intel.gitlab import members
from cartography.intel.gitlab import projects
from cartography.intel.gitlab.common import get_web_base_url


def test_get_web_base_url() -> None:
    assert get_web_base_url(None) is None
    assert get_web_base_url("gitlab.acme.com/") == "https://gitlab.acme.com"
    assert get_web_base_url("http://gitlab.internal") == "http://gitlab.internal"
    assert get_web_base_url("https://user:token@gitlab.example.com/") == "https://gitlab.example.com"
    assert get_web_base_url("javascript://example.com") is None


def test_transforms_set_console_links() -> None:
    host = "https://gitlab.acme.com"

    assert group.transform_groups([{"full_path": "acme/platform"}], host)[0]["consolelink"] == (
        "https://gitlab.acme.com/acme/platform"
    )
    project = projects.transform_projects_data([{"visibility": "private", "path_with_namespace": "acme/api"}], host)[0]
    assert project["consolelink"] == "https://gitlab.acme.com/acme/api"

    branch = projects.transform_branches_data([{"name": "feature/x"}], 1, "acme/api", "main", host)[0]
    assert branch["consolelink"] == "https://gitlab.acme.com/acme/api/-/tree/feature/x"

    member_rows = members.transform_members([{"username": "alice"}, {}], None)
    assert member_rows[0]["consolelink"] == "https://gitlab.com/alice"
    assert member_rows[1]["consolelink"] is None
