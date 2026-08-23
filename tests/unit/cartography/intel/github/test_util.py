from unittest.mock import patch

import pytest
import requests

from cartography.intel.github.util import fetch_all


@patch("cartography.intel.github.util.time.sleep")
@patch("cartography.intel.github.util.fetch_page")
def test_fetch_all_re_raises_original_timeout(mock_fetch_page, mock_sleep):
    mock_fetch_page.side_effect = requests.exceptions.Timeout("Connection timed out")

    with pytest.raises(requests.exceptions.Timeout) as exc_info:
        fetch_all(
            token="dummy_token",
            api_url="https://api.github.com/graphql",
            organization="test_org",
            query="test_query",
            resource_type="repositories",
            field_name="nodes",
            retries=3,
        )

    assert "Connection timed out" in str(exc_info.value)
    assert mock_fetch_page.call_count == 3


@patch("cartography.intel.github.util.time.sleep")
@patch("cartography.intel.github.util.fetch_page")
def test_fetch_all_re_raises_original_http_error(mock_fetch_page, mock_sleep):
    mock_fetch_page.side_effect = requests.exceptions.HTTPError("403 Client Error: Forbidden")

    with pytest.raises(requests.exceptions.HTTPError) as exc_info:
        fetch_all(
            token="dummy_token",
            api_url="https://api.github.com/graphql",
            organization="test_org",
            query="test_query",
            resource_type="repositories",
            field_name="nodes",
            retries=2,
        )

    assert "403 Client Error: Forbidden" in str(exc_info.value)
    assert mock_fetch_page.call_count == 2


@patch("cartography.intel.github.util.fetch_page")
def test_fetch_all_success_with_zero_retries(mock_fetch_page):
    mock_fetch_page.return_value = {
        "data": {
            "organization": {
                "url": "https://github.com/test_org",
                "login": "test_org",
                "repositories": {
                    "nodes": [{"name": "repo1"}],
                    "pageInfo": {
                        "endCursor": "cursor1",
                        "hasNextPage": False,
                    },
                },
            },
        },
    }

    data, org_data = fetch_all(
        token="dummy_token",
        api_url="https://api.github.com/graphql",
        organization="test_org",
        query="test_query",
        resource_type="repositories",
        field_name="nodes",
        retries=0,
    )

    assert len(data) == 1
    assert data[0]["name"] == "repo1"
    assert org_data["login"] == "test_org"
