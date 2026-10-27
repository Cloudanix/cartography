import logging
from typing import Any
from urllib.parse import quote
from urllib.parse import urljoin
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

BASE_URL = "https://rest.ripplingapis.com"
PAGE_LIMIT = 100
REQUEST_TIMEOUT = 60


class RipplingRequestError(Exception):
    def __init__(self, status_code: int, url: str) -> None:
        super().__init__(f"Rippling API {status_code} for {url}")
        self.status_code = status_code
        self.url = url


class MembersUnavailable(RipplingRequestError):
    """GET /supergroups/{id}/members/ returned 404. Membership is unknown, not empty."""


def _headers(access_token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }


def _request(
    access_token: str,
    url: str,
    params: dict[str, Any] | None,
    *,
    members_call: bool = False,
) -> Any:
    response = requests.get(
        url,
        headers=_headers(access_token),
        params=params,
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code == 404 and members_call:
        raise MembersUnavailable(response.status_code, url)
    if response.status_code >= 400:
        raise RipplingRequestError(response.status_code, url)
    return response.json()


def _next_url(current: str, next_link: str | None) -> str | None:
    if not next_link:
        return None
    if urlparse(next_link).scheme:
        return next_link
    if next_link.startswith("/"):
        return urljoin(BASE_URL, next_link)
    return urljoin(current, next_link)


def list_results(
    access_token: str,
    path: str,
    params: dict[str, Any] | None = None,
    *,
    members_call: bool = False,
) -> list[dict[str, Any]]:
    """Follow cursor pagination. `next_link` already carries limit and cursor."""
    url: str | None = urljoin(BASE_URL, path)
    query = {"limit": PAGE_LIMIT}
    if params:
        query.update(params)
    rows: list[dict[str, Any]] = []
    while url:
        payload = _request(access_token, url, query, members_call=members_call)
        query = None
        if isinstance(payload, list):
            rows.extend(item for item in payload if isinstance(item, dict))
            break
        if not isinstance(payload, dict):
            break
        results = payload.get("results")
        if isinstance(results, list):
            rows.extend(item for item in results if isinstance(item, dict))
        elif payload.get("id"):
            rows.append(payload)
            break
        url = _next_url(url, payload.get("next_link"))
    return rows


def list_members(access_token: str, supergroup_id: str) -> list[dict[str, Any]] | None:
    """Return members, or None when Rippling answers 404 (membership unknown)."""
    path = f"/supergroups/{quote(supergroup_id, safe='')}/members/"
    try:
        return list_results(access_token, path, members_call=True)
    except MembersUnavailable:
        logger.info("supergroup members unavailable", extra={"supergroup_id": supergroup_id})
        return None
