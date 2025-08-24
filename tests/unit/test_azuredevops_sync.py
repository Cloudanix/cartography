import pytest
from unittest.mock import Mock, patch, MagicMock
from cartography.intel.azuredevops import (
    start_azure_devops_ingestion,
    sync_organization,
    validate_auth_config,
)


class TestAuthConfigValidation:
    """Test authentication configuration validation."""

    def test_validate_auth_config_valid(self):
        """Test valid auth configuration."""
        config = {
            "accounts": [
                {
                    "tenant_id": "tenant1",
                    "client_id": "client1",
                    "client_secret": "secret1",
                    "url": "https://dev.azure.com",
                    "organization_names": ["org1", "org2"],
                }
            ]
        }
        assert validate_auth_config(config) is True

    def test_validate_auth_config_missing_accounts(self):
        """Test config missing accounts."""
        config = {}
        assert validate_auth_config(config) is False

    def test_validate_auth_config_empty_accounts(self):
        """Test config with empty accounts list."""
        config = {"accounts": []}
        assert validate_auth_config(config) is False

    def test_validate_auth_config_missing_required_fields(self):
        """Test config missing required fields."""
        config = {
            "accounts": [
                {
                    "tenant_id": "tenant1",
                    "client_id": "client1",
                    # Missing other required fields
                }
            ]
        }
        assert validate_auth_config(config) is False

    def test_validate_auth_config_empty_org_names(self):
        """Test config with empty organization names."""
        config = {
            "accounts": [
                {
                    "tenant_id": "tenant1",
                    "client_id": "client1",
                    "client_secret": "secret1",
                    "url": "https://dev.azure.com",
                    "organization_names": [],
                }
            ]
        }
        assert validate_auth_config(config) is False


class TestSyncOrganization:
    """Test organization sync functionality."""

    @patch("cartography.intel.azuredevops.organization.sync")
    @patch("cartography.intel.azuredevops.RESOURCE_FUNCTIONS")
    def test_sync_organization_success(self, mock_resource_functions, mock_org_sync):
        """Test successful organization sync."""
        mock_resource_functions.keys.return_value = ["projects", "repos", "members"]
        mock_resource_functions.__getitem__.side_effect = lambda x: Mock()

        mock_session = Mock()
        mock_config = Mock()
        mock_config.neo4j_user = "user"
        mock_config.neo4j_password = "pass"
        mock_config.neo4j_uri = "bolt://localhost:7687"
        mock_config.neo4j_max_connection_lifetime = 3600

        sync_organization(
            mock_session,
            mock_config,
            "test-org",
            "https://dev.azure.com",
            "token",
            {"UPDATE_TAG": "tag", "WORKSPACE_ID": "workspace"},
        )

        mock_org_sync.assert_called_once()

    @patch("cartography.intel.azuredevops.organization.sync")
    def test_sync_organization_request_exception(self, mock_org_sync):
        """Test organization sync with request exception."""
        mock_org_sync.side_effect = Exception("API Error")

        mock_session = Mock()
        mock_config = Mock()
        mock_config.neo4j_user = "user"
        mock_config.neo4j_password = "pass"
        mock_config.neo4j_uri = "bolt://localhost:7687"
        mock_config.neo4j_max_connection_lifetime = 3600

        # Should not raise exception
        sync_organization(
            mock_session,
            mock_config,
            "test-org",
            "https://dev.azure.com",
            "token",
            {"UPDATE_TAG": "tag", "WORKSPACE_ID": "workspace"},
        )


class TestStartAzureDevOpsIngestion:
    """Test main ingestion function."""

    def test_start_azure_devops_ingestion_no_config(self):
        """Test ingestion with no configuration."""
        mock_session = Mock()
        mock_config = Mock()
        mock_config.azure_devops_config = None

        start_azure_devops_ingestion(mock_session, mock_config)
        # Should return without error

    @patch("cartography.intel.azuredevops.get_access_token")
    @patch("cartography.intel.azuredevops.sync_organization")
    def test_start_azure_devops_ingestion_success(self, mock_sync_org, mock_get_token):
        """Test successful ingestion."""
        mock_session = Mock()
        mock_config = Mock()
        mock_config.azure_devops_config = "eyJvcmdhbml6YXRpb24iOlt7InRlbmFudF9pZCI6InRlbmFudDEiLCJjbGllbnRfaWQiOiJjbGllbnQxIiwiY2xpZW50X3NlY3JldCI6InNlY3JldDEiLCJ1cmwiOiJodHRwczovL2Rldi5henVyZS5jb20iLCJuYW1lIjoib3JnMSJ9XX0="  # {"organization":[{"tenant_id":"tenant1","client_id":"client1","client_secret":"secret1","url":"https://dev.azure.com","name":"org1"}]} in base64
        mock_config.params = {
            "workspace": {"id_string": "workspace", "account_id": "org1"}
        }
        mock_config.update_tag = "tag"

        mock_get_token.return_value = "access-token"

        start_azure_devops_ingestion(mock_session, mock_config)

        mock_get_token.assert_called_once()
        mock_sync_org.assert_called_once()

    def test_start_azure_devops_ingestion_invalid_config(self):
        """Test ingestion with invalid configuration."""
        mock_session = Mock()
        mock_config = Mock()
        mock_config.azure_devops_config = "invalid-base64"

        start_azure_devops_ingestion(mock_session, mock_config)
        # Should return without error

    def test_start_azure_devops_ingestion_invalid_json(self):
        """Test ingestion with invalid JSON in config."""
        mock_session = Mock()
        mock_config = Mock()
        mock_config.azure_devops_config = "bm90LWpzb24="  # "not-json" in base64

        start_azure_devops_ingestion(mock_session, mock_config)
        # Should return without error

    @patch("cartography.intel.azuredevops.get_access_token")
    def test_start_azure_devops_ingestion_token_failure(self, mock_get_token):
        """Test ingestion with token retrieval failure."""
        mock_session = Mock()
        mock_config = Mock()
        mock_config.azure_devops_config = "eyJvcmdhbml6YXRpb24iOlt7InRlbmFudF9pZCI6InRlbmFudDEiLCJjbGllbnRfaWQiOiJjbGllbnQxIiwiY2xpZW50X3NlY3JldCI6InNlY3JldDEiLCJ1cmwiOiJodHRwczovL2Rldi5henVyZS5jb20iLCJuYW1lIjoib3JnMSJ9XX0="  # {"organization":[{"tenant_id":"tenant1","client_id":"client1","client_secret":"secret1","url":"https://dev.azure.com","name":"org1"}]} in base64
        mock_config.params = {
            "workspace": {"id_string": "workspace", "account_id": "org1"}
        }
        mock_config.update_tag = "tag"

        mock_get_token.return_value = None

        start_azure_devops_ingestion(mock_session, mock_config)

        mock_get_token.assert_called_once()
        # Should continue without error
