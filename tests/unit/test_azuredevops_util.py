from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests

from cartography.intel.azuredevops.util import call_azure_devops_api
from cartography.intel.azuredevops.util import call_azure_devops_api_pagination
from cartography.intel.azuredevops.util import get_access_token
from cartography.intel.azuredevops.util import validate_organization_data
from cartography.intel.azuredevops.util import validate_project_data
from cartography.intel.azuredevops.util import validate_repository_data
from cartography.intel.azuredevops.util import validate_user_data


class TestDataValidation:
    """Test data validation functions to ensure they correctly identify valid and invalid data structures."""

    @pytest.mark.parametrize(
        "data, expected",
        [
            ({"name": "test-org", "url": "https://dev.azure.com/test-org"}, True),
            ({"url": "https://dev.azure.com/test-org"}, False),
            ({"name": "", "url": "https://dev.azure.com/test-org"}, False),
            ({}, False),
        ],
    )
    def test_validate_organization_data(self, data, expected):
        """Test validation of organization data with various inputs."""
        assert validate_organization_data(data) is expected

    @pytest.mark.parametrize(
        "data, expected",
        [
            (
                {
                    "id": "project-id",
                    "name": "test-project",
                    "url": "https://dev.azure.com/org/project",
                },
                True,
            ),
            (
                {"name": "test-project", "url": "https://dev.azure.com/org/project"},
                False,
            ),
            (
                {
                    "id": "",
                    "name": "test-project",
                    "url": "https://dev.azure.com/org/project",
                },
                False,
            ),
        ],
    )
    def test_validate_project_data(self, data, expected):
        """Test validation of project data with various inputs."""
        assert validate_project_data(data) is expected

    @pytest.mark.parametrize(
        "data, expected",
        [
            (
                {
                    "id": "repo-id",
                    "name": "test-repo",
                    "url": "https://dev.azure.com/org/project/_git/repo",
                },
                True,
            ),
            ({"id": "repo-id", "name": "test-repo"}, False),
            (
                {
                    "id": "repo-id",
                    "name": "test-repo",
                    "url": "",
                },
                False,
            ),
        ],
    )
    def test_validate_repository_data(self, data, expected):
        """Test validation of repository data with various inputs."""
        assert validate_repository_data(data) is expected

    @pytest.mark.parametrize(
        "data, expected",
        [
            (
                {
                    "id": "user-id",
                    "user": {
                        "displayName": "Test User",
                        "principalName": "test@example.com",
                    },
                },
                True,
            ),
            ({"id": "user-id"}, False),
            (
                {
                    "id": "user-id",
                    "user": {"principalName": "test@example.com"},
                },
                False,
            ),
            (
                {
                    "id": "user-id",
                    "user": {
                        "displayName": "",
                        "principalName": "test@example.com",
                    },
                },
                False,
            ),
        ],
    )
    def test_validate_user_data(self, data, expected):
        """Test validation of user data with various inputs."""
        assert validate_user_data(data) is expected


class TestMicrosoftEntraIDAuthentication:
    """Test Microsoft Entra ID OAuth authentication functions."""

    @patch("cartography.intel.azuredevops.util.requests.post")
    def test_get_access_token_success(self, mock_post):
        """Test successful access token retrieval."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "test-token",
            "expires_in": 3600,
            "token_type": "Bearer",
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        token = get_access_token("tenant", "client", "secret")
        assert token == "test-token"
        mock_post.assert_called_once()

    @patch("cartography.intel.azuredevops.util.requests.post")
    @patch("cartography.intel.azuredevops.util.time.sleep", return_value=None)
    def test_get_access_token_retry_on_failure(self, mock_sleep, mock_post):
        """Test access token retrieval with retry logic on network errors."""
        mock_post.side_effect = [
            requests.exceptions.RequestException("Network error"),
            requests.exceptions.RequestException("Network error"),
            MagicMock(
                json=lambda: {"access_token": "test-token", "expires_in": 3600},
                raise_for_status=lambda: None,
            ),
        ]

        token = get_access_token("tenant", "client", "secret")
        assert token == "test-token"
        assert mock_post.call_count == 3

    @patch("cartography.intel.azuredevops.util.requests.post")
    def test_get_access_token_failure_after_retries(self, mock_post):
        """Test that an exception is raised after all retries fail."""
        mock_post.side_effect = requests.exceptions.RequestException("Network error")
        with pytest.raises(requests.exceptions.RequestException):
            get_access_token("tenant", "client", "secret")
        assert mock_post.call_count == 3


class TestAPICalls:
    """Test API call functions with Microsoft Entra ID OAuth."""

    @patch("cartography.intel.azuredevops.util.requests.request")
    def test_call_azure_devops_api_success(self, mock_request):
        """Test a successful API call."""
        mock_response = MagicMock()
        mock_response.json.return_value = {"data": "test"}
        mock_response.status_code = 200
        mock_request.return_value = mock_response

        result = call_azure_devops_api("https://test.com", "token", "GET")
        assert result == {"data": "test"}

        # Verify that the correct headers were sent
        mock_request.assert_called_once()
        headers = mock_request.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer token"
        assert headers["User-Agent"] == "Cartography-AzureDevOps/1.0"

    @patch("cartography.intel.azuredevops.util.requests.request")
    def test_call_azure_devops_api_no_content(self, mock_request):
        """Test an API call that returns a 204 No Content status."""
        mock_response = MagicMock(status_code=204)
        mock_request.return_value = mock_response

        result = call_azure_devops_api("https://test.com", "token", "GET")
        assert result is None

    @patch("cartography.intel.azuredevops.util.requests.request")
    @patch("cartography.intel.azuredevops.util.time.sleep", return_value=None)
    def test_call_azure_devops_api_retry_on_500(self, mock_sleep, mock_request):
        """Test that the API call is retried on a 500 server error."""
        mock_request.side_effect = [
            MagicMock(
                status_code=500,
                headers={},
                text="Server Error",
                raise_for_status=MagicMock(
                    side_effect=requests.exceptions.HTTPError(
                        response=MagicMock(status_code=500, headers={}),
                    ),
                ),
            ),
            MagicMock(
                json=lambda: {"data": "test"},
                status_code=200,
            ),
        ]

        result = call_azure_devops_api("https://test.com", "token", "GET")
        assert result == {"data": "test"}
        assert mock_request.call_count == 2

    @patch("cartography.intel.azuredevops.util.call_azure_devops_api")
    def test_call_azure_devops_api_pagination(self, mock_api_call):
        """Test the pagination logic for API calls."""
        # Simulate two pages of results
        mock_response_page1 = MagicMock()
        mock_response_page1.get.return_value = [{"id": 1}, {"id": 2}]
        mock_response_page1.headers = {"x-ms-continuationtoken": "token2"}

        mock_response_page2 = MagicMock()
        mock_response_page2.get.return_value = [{"id": 3}, {"id": 4}]
        mock_response_page2.headers = {}

        mock_api_call.side_effect = [
            mock_response_page1,
            mock_response_page2,
        ]

        results = call_azure_devops_api_pagination("https://test.com/api", "token")
        assert len(results) == 4
        assert results == [{"id": 1}, {"id": 2}, {"id": 3}, {"id": 4}]
        assert mock_api_call.call_count == 2
