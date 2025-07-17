import logging

import requests

from cartography.util import make_requests_url


logger = logging.getLogger(__name__)

def paginate_request(url: str, access_token: str):
    items = []
    while url:
        response = make_requests_url(url, access_token, return_raw=True)

        if not isinstance(response, requests.Response):
            break

        try:
            data = response.json()
        except requests.exceptions.JSONDecodeError:
            logger.warning(f"Failed to decode JSON from response for URL: {url}")
            break

        if isinstance(data, list):
            items.extend(data)
        elif isinstance(data, dict):
            items.append(data)

        if "next" in response.links:
            url = response.links["next"]["url"]
        else:
            url = None

    return items
