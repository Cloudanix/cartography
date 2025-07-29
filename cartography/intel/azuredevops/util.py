import logging
import requests
import base64
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)
TIMEOUT = (60, 60)


def get_access_token(tenant_id, client_id, client_secret, refresh_token):
    """
    Exchanges a refresh token for a new OAuth 2.0 access token.
    """
    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": "499b84ac-1321-427f-aa17-267ca6975798/.default",  # Azure DevOps resource ID
    }
    response = requests.post(token_url, data=data, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()["access_token"]


def call_azure_devops_api(
    url: str,
    access_token: str,
    method: str = "GET",
    params: Optional[Dict] = None,
    json_data: Optional[Dict] = None,
) -> Optional[Dict]:
    """
    Calls the Azure DevOps REST API.
    """
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {access_token}',
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