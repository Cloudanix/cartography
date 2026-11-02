from functools import partial
from typing import Optional

from cartography.intel import git_links


GITLAB_HOST = "gitlab.com"


def get_web_base_url(hosted_domain: Optional[str]) -> Optional[str]:
    """
    Normalize the configured GitLab host to a base URL ("gitlab.acme.com" -> "https://gitlab.acme.com").
    None means gitlab.com, and so does a host that is not plain http(s); credentials never reach the link.
    """
    if not hosted_domain:
        return None
    return git_links.safe_base_url(hosted_domain if "://" in hosted_domain else f"https://{hosted_domain}")


def get_node_id(hosted_domain: Optional[str], key: git_links.ScmKey) -> git_links.ScmKey:
    """
    Graph id for a GitLab group (full path), member (username) or project (numeric id). Those are unique only
    within one GitLab instance, so a self-managed instance's are keyed "<host>/<key>"; gitlab.com keeps the bare
    key it has always had.

    :param hosted_domain: the configured GitLab host; None means gitlab.com
    :param key: the native id
    """
    return git_links.host_scoped_key(get_web_base_url(hosted_domain), GITLAB_HOST, key)


# Web link for a GitLab entity, or None (logged) when an identifier is missing; never fails a sync.
get_console_link = partial(git_links.get_console_link, "gitlab")
