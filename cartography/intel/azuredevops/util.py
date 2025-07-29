import logging
import requests
import base64
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)
TIMEOUT = (60, 60)


def call_azure_devops_api(
    url: str,
    token: str,
    method: str = "GET",
    params: Optional[Dict] = None,
    json_data: Optional[Dict] = None,
) -> Optional[Dict]:
    """
    Calls the Azure DevOps REST API.
    """
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Basic {base64.b64encode(f":{token}".encode("ascii")).decode("ascii")}'
    }
    try:
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            json=json_data,
            timeout=TIMEOUT
        )
        response.raise_for_status()
        if response.status_code == 204:  # No Content
            return None
        return response.json()
    except requests.exceptions.HTTPError as e:
        logger.error(
            f"Error calling Azure DevOps API: {e}. "
            f"URL: {url}, Status: {e.response.status_code}, Response: {e.response.text}",
        )
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Error calling Azure DevOps API at {url}: {e}")
        return None 