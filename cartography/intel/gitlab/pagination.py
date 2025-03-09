import logging

from cartography.util import make_requests_url


logger = logging.getLogger(__name__)

def paginate_request(url: str, access_token: str):
    items = []
    while url:
        response = make_requests_url(url, access_token, return_raw=True)
        if isinstance(response, list):
            items.extend(response)

        elif isinstance(response, dict):
            items.append(response)

        # Check for pagination
        if "next" in response.links:
            url = response.links["next"]["url"]

        else:
            url = None

    return items
