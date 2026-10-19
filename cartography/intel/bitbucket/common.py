import logging
from typing import Optional

from cloudconsolelink.clouds.git import GitLinker

logger = logging.getLogger(__name__)
git_linker = GitLinker()


def cleanse_string(val: str) -> str:
    return val.strip()


def get_console_link(resource_name: str, **params: Optional[str]) -> Optional[str]:
    """
    Web link for a Bitbucket Cloud entity, or None (logged) when an identifier is missing; never fails a sync.
    """
    try:
        link: str = git_linker.get_console_link("bitbucket", resource_name, **params)
    except ValueError as e:
        logger.debug(f"Skipping Bitbucket {resource_name} console link: {e}")
        return None
    return link
