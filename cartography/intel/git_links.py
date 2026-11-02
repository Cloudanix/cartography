import logging
from typing import Optional
from typing import Union
from urllib.parse import urlparse

from cloudconsolelink.clouds.git import GitLinker

logger = logging.getLogger(__name__)
git_linker = GitLinker()
WEB_SCHEMES = ("http", "https")
# A native SCM id: a login / path / name, or GitLab's numeric project id (kept an int on gitlab.com).
ScmKey = Optional[Union[str, int]]


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


def host_scoped_key(base_url: Optional[str], saas_host: str, key: ScmKey) -> ScmKey:
    """
    Graph key for an SCM entity whose native id is unique only within one instance: an org login, a GitLab
    group path, username or numeric project id, an Azure DevOps organization (collection) name.

    On the SaaS host the bare key stays, the id these nodes have always had, so github.com / gitlab.com /
    dev.azure.com assets keep their identity. Any other host (GitHub Enterprise Server, GHE.com, self-managed
    GitLab, Azure DevOps Server) gets "<host>[:port][/path]/<key>", so two instances' "platform" never MERGE
    into one node that two tenants then share.

    :param base_url: the configured web/API base url of the instance; None, or a url that is not plain http(s),
        means the SaaS host (the same fallback the console links use)
    :param saas_host: the provider's public host, e.g. "github.com"
    :param key: the native id; None stays None
    :return: the key, host-qualified unless the instance is the SaaS host
    """
    base = safe_base_url(base_url)
    if key is None or not base or urlparse(base).hostname == saas_host:
        return key
    return f"{base.split('://', 1)[1]}/{key}"


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
