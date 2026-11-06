from cartography.intel.azuredevops import members
from cartography.intel.azuredevops import repos
from cartography.intel.azuredevops.util import get_console_link


def test_branch_console_link_encodes_branch_in_query() -> None:
    branch = repos.transform_branches_data(
        [{"name": "feature/x"}], "r1", "feature/x", "https://dev.azure.com", "acme", "My Project", "api",
    )[0]
    assert branch["consolelink"] == "https://dev.azure.com/acme/My%20Project/_git/api?version=GBfeature%2Fx"


def test_console_link_is_none_when_identifier_missing() -> None:
    assert repos.transform_branches_data([{"name": "main"}], "r1", "main")[0]["consolelink"] is None
    assert get_console_link("project", organization="acme", project=None) is None


def test_user_gets_the_organization_users_page() -> None:
    link = get_console_link("user", base_url="https://dev.azure.com", organization="acme")
    assert link == "https://dev.azure.com/acme/_settings/users"
    assert members.transform_user({"id": "u1"}, link)["consolelink"] == link
