import logging
from typing import Optional
from urllib.parse import urlparse

from cloudconsolelink.clouds.git import GitLinker

logger = logging.getLogger(__name__)
git_linker = GitLinker()
WEB_SCHEMES = ("http", "https")


def safe_base_url(url: Optional[str], keep_path: bool = True) -> Optional[str]:
    """
    Reduce a configured host url to a link-safe base: scheme://host[:port][/path].

    :param url: customer-configured url, e.g. "https://user:token@gitlab.acme.com/gitlab/"
    :param keep_path: keep the path (self-managed hosts served under a sub-path) or drop it
    :return: the base url without userinfo, query or fragment ("https://gitlab.acme.com/gitlab"),
        or None when the url is not plain http(s); links are stored and opened from the console,
        so an embedded token or a javascript: scheme must never reach them.
    """
    parsed = urlparse(url or "")
    try:
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in WEB_SCHEMES or not parsed.hostname:
        return None
    base = f"{parsed.scheme}://{parsed.hostname}{f':{port}' if port else ''}"
    return f"{base}{parsed.path}".rstrip("/") if keep_path else base


def get_console_link(
    provider: str, resource_name: str, base_url: Optional[str] = None, **params: Optional[str],
) -> Optional[str]:
    """
    Web link for a GitHub, GitLab, Bitbucket or Azure DevOps entity; never fails a sync.

    :param provider: "github", "gitlab", "bitbucket" or "azuredevops"
    :param resource_name: entity type, e.g. "repository", "branch"
    :param base_url: host override (GitHub Enterprise, self-managed GitLab); None means the public host
    :param params: identifiers the link template needs, e.g. owner="acme", repo="api"
    :return: the link, or None (logged at debug) when an identifier is missing or base_url is not safe http(s)
    """
    safe_base = safe_base_url(base_url)
    if base_url and not safe_base:
        logger.debug(f"Skipping {provider} {resource_name} console link: base url is not http(s)")
        return None
    try:
        link: str = git_linker.get_console_link(provider, resource_name, base_url=safe_base, **params)
    except ValueError as e:
        logger.debug(f"Skipping {provider} {resource_name} console link: {e}")
        return None
    return link
