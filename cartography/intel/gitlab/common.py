from functools import partial
from typing import Optional

from cartography.intel import git_links


def get_web_base_url(hosted_domain: Optional[str]) -> Optional[str]:
    """
    Normalize the configured GitLab host to a base URL ("gitlab.acme.com" -> "https://gitlab.acme.com").
    None means gitlab.com, and so does a host that is not plain http(s); credentials never reach the link.
    """
    if not hosted_domain:
        return None
    return git_links.safe_base_url(hosted_domain if "://" in hosted_domain else f"https://{hosted_domain}")


# Web link for a GitLab entity, or None (logged) when an identifier is missing; never fails a sync.
get_console_link = partial(git_links.get_console_link, "gitlab")
