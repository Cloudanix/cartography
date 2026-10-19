import logging
from typing import Optional

from cloudconsolelink.clouds.git import GitLinker

logger = logging.getLogger(__name__)
git_linker = GitLinker()


def get_web_base_url(hosted_domain: Optional[str]) -> Optional[str]:
    """
    Normalize the configured GitLab host to a base URL ("gitlab.acme.com" -> "https://gitlab.acme.com").
    None means gitlab.com.
    """
    if not hosted_domain:
        return None
    base = hosted_domain if "://" in hosted_domain else f"https://{hosted_domain}"
    return base.rstrip("/")


def get_console_link(resource_name: str, base_url: Optional[str] = None, **params: Optional[str]) -> Optional[str]:
    """
    Web link for a GitLab entity, or None (logged) when an identifier is missing; never fails a sync.
    """
    try:
        link: str = git_linker.get_console_link("gitlab", resource_name, base_url=base_url, **params)
    except ValueError as e:
        logger.debug(f"Skipping GitLab {resource_name} console link: {e}")
        return None
    return link
