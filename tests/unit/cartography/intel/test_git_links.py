from cartography.intel import git_links


def test_safe_base_url_drops_credentials_and_rejects_non_http_schemes() -> None:
    assert git_links.safe_base_url("https://user:ghp_x@ghe.acme.com:8443/gitlab/?q=1#f") == (
        "https://ghe.acme.com:8443/gitlab"
    )
    assert git_links.safe_base_url("https://user:ghp_x@ghe.acme.com/api/graphql", keep_path=False) == (
        "https://ghe.acme.com"
    )
    assert git_links.safe_base_url("http://gitlab.internal/") == "http://gitlab.internal"
    assert git_links.safe_base_url("javascript://evil.com") is None
    assert git_links.safe_base_url("https://host:notaport") is None
    assert git_links.safe_base_url(None) is None


def test_get_console_link_never_builds_a_link_from_an_unsafe_base_url() -> None:
    assert git_links.get_console_link("gitlab", "group", base_url="javascript://evil.com", group_path="g") is None
    assert git_links.get_console_link(
        "azuredevops", "organization", base_url="https://pat:secret@dev.azure.com/", organization="acme",
    ) == "https://dev.azure.com/acme"
    assert git_links.get_console_link("bitbucket", "workspace", workspace="acme") == "https://bitbucket.org/acme"


def test_host_scoped_key_keeps_saas_keys_and_qualifies_other_hosts() -> None:
    # SaaS ids stay as they are (no console churn), whatever their type.
    assert git_links.host_scoped_key("https://github.com", "github.com", "acme") == "acme"
    assert git_links.host_scoped_key("https://gitlab.com", "gitlab.com", 42) == 42
    assert git_links.host_scoped_key("https://dev.azure.com", "dev.azure.com", "acme") == "acme"
    assert git_links.host_scoped_key(None, "gitlab.com", "platform") == "platform"
    assert git_links.host_scoped_key("javascript://evil.com", "gitlab.com", "platform") == "platform"
    # Any other instance: host (and port / sub-path), never credentials.
    assert git_links.host_scoped_key("https://ghe.acme.com", "github.com", "acme") == "ghe.acme.com/acme"
    assert git_links.host_scoped_key(
        "https://user:glpat@GitLab.Acme.com:8443/gitlab/", "gitlab.com", 42,
    ) == "gitlab.acme.com:8443/gitlab/42"
    assert git_links.host_scoped_key("https://ado.acme.com/tfs", "dev.azure.com", "DefaultCollection") == (
        "ado.acme.com/tfs/DefaultCollection"
    )
    assert git_links.host_scoped_key("https://ghe.acme.com", "github.com", None) is None
