from functools import partial

from cartography.intel import git_links


def cleanse_string(val: str) -> str:
    return val.strip()


# Web link for a Bitbucket Cloud entity, or None (logged) when an identifier is missing; never fails a sync.
get_console_link = partial(git_links.get_console_link, "bitbucket")
