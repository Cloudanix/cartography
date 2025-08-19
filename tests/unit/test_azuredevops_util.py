import pytest
from unittest.mock import Mock, patch
from cartography.intel.azuredevops.util import (
    validate_organization_data,
    validate_project_data,
    validate_repository_data,
    validate_user_data,
    get_access_token,
    call_azure_devops_api,
)


class TestDataValidation:
    """Test data validation functions."""

    def test_validate_organization_data_valid(self):
        """Test valid organization data."""
        data = {"name": "test-org", "url": "https://dev.azure.com/test-org"}
        assert validate_organization_data(data) is True

    def test_validate_organization_data_missing_name(self):
        """Test organization data missing name."""
        data = {"url": "https://dev.azure.com/test-org"}
        assert validate_organization_data(data) is False

    def test_validate_organization_data_empty_name(self):
        """Test organization data with empty name."""
        data = {"name": "", "url": "https://dev.azure.com/test-org"}
        assert validate_organization_data(data) is False

    def test_validate_project_data_valid(self):
        """Test valid project data."""
        data = {
            "id": "project-id",
            "name": "test-project",
            "url": "https://dev.azure.com/org/project",
        }
        assert validate_project_data(data) is True

    def test_validate_project_data_missing_id(self):
        """Test project data missing id."""
        data = {"name": "test-project", "url": "https://dev.azure.com/org/project"}
        assert validate_project_data(data) is False

    def test_validate_repository_data_valid(self):
        """Test valid repository data."""
        data = {
            "id": "repo-id",
            "name": "test-repo",
            "url": "https://dev.azure.com/org/project/_git/repo",
        }
        assert validate_repository_data(data) is True

    def test_validate_repository_data_missing_url(self):
        """Test repository data missing url."""
        data = {"id": "repo-id", "name": "test-repo"}
        assert validate_repository_data(data) is False

    def test_validate_user_data_valid(self):
        """Test valid user data."""
        data = {
            "id": "user-id",
            "user": {"displayName": "Test User", "principalName": "test@example.com"},
        }
        assert validate_user_data(data) is True

    def test_validate_user_data_missing_user(self):
        """Test user data missing user object."""
        data = {"id": "user-id"}
        assert validate_user_data(data) is False

    def test_validate_user_data_missing_display_name(self):
        """Test user data missing display name."""
        data = {
            "id": "user-id",
            "user": {"principalName": "test@example.com"},
        }
        assert validate_user_data(data) is False


class TestMicrosoftEntraIDAuthentication:
    """Test Microsoft Entra ID OAuth authentication functions."""

    @patch("cartography.intel.azuredevops.util.requests.post")
    def test_get_access_token_success(self, mock_post):
        """Test successful access token retrieval using Microsoft Entra ID."""
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

    @patch("cartography.intel.azuredevops.util.requests.post")
    def test_get_access_token_retry_on_failure(self, mock_post):
        """Test access token retrieval with retry logic."""
        mock_post.side_effect = [
            Exception("Network error"),
            Exception("Network error"),
            Mock(
                json=lambda: {"access_token": "test-token", "expires_in": 3600},
                raise_for_status=lambda: None,
            ),
        ]

        token = get_access_token("tenant", "client", "secret")
        assert token == "test-token"
        assert mock_post.call_count == 3

    @patch("cartography.intel.azuredevops.util.requests.post")
    def test_get_access_token_missing_token_in_response(self, mock_post):
        """Test access token retrieval with invalid response."""
        mock_response = Mock()
        mock_response.json.return_value = {"error": "invalid_grant"}
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        with pytest.raises(ValueError, match="Access token not found in response"):
            get_access_token("tenant", "client", "secret")

    @patch("cartography.intel.azuredevops.util.requests.post")
    def test_get_access_token_with_expiry_logging(self, mock_post):
        """Test access token retrieval with expiry logging."""
        mock_response = Mock()
        mock_response.json.return_value = {
            "access_token": "test-token",
            "expires_in": 7200,
        }
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response

        token = get_access_token("tenant", "client", "secret")
        assert token == "test-token"


class TestAPICalls:
    """Test API call functions with Microsoft Entra ID OAuth."""

    @patch("cartography.intel.azuredevops.util.requests.request")
    def test_call_azure_devops_api_success(self, mock_request):
        """Test successful API call with proper headers."""
        mock_response = Mock()
        mock_response.json.return_value = {"data": "test"}
        mock_response.status_code = 200
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        result = call_azure_devops_api("https://test.com", "token")
        assert result == {"data": "test"}

        # Verify proper headers were sent
        mock_request.assert_called_once()
        call_args = mock_request.call_args
        headers = call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer token"
        assert headers["User-Agent"] == "Cartography-AzureDevOps/1.0"

    @patch("cartography.intel.azuredevops.util.requests.request")
    def test_call_azure_devops_api_no_content(self, mock_request):
        """Test API call returning no content."""
        mock_response = Mock()
        mock_response.status_code = 204
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response

        result = call_azure_devops_api("https://test.com", "token")
        assert result is None

    @patch("cartography.intel.azuredevops.util.requests.request")
    def test_call_azure_devops_api_retry_on_500(self, mock_request):
        """Test API call retry on server error."""
        mock_request.side_effect = [
            Mock(status_code=500, headers={}, text="Server Error"),
            Mock(
                json=lambda: {"data": "test"},
                status_code=200,
                raise_for_status=lambda: None,
            ),
        ]

        result = call_azure_devops_api("https://test.com", "token")
        assert result == {"data": "test"}
        assert mock_request.call_count == 2

    @patch("cartography.intel.azuredevops.util.requests.request")
    def test_call_azure_devops_api_rate_limiting(self, mock_request):
        """Test API call handling rate limiting."""
        mock_request.side_effect = [
            Mock(
                status_code=429,
                headers={"Retry-After": "5"},
                text="Rate Limited",
            ),
            Mock(
                json=lambda: {"data": "test"},
                status_code=200,
                raise_for_status=lambda: None,
            ),
        ]

        result = call_azure_devops_api("https://test.com", "token")
        assert result == {"data": "test"}
        assert mock_request.call_count == 2
