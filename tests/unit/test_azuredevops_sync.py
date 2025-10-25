import base64
import json
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

import pytest

from cartography.config import Config
from cartography.intel.azuredevops import start_azure_devops_ingestion
from cartography.intel.azuredevops import sync_organization
from cartography.intel.azuredevops import validate_auth_config


class TestAuthConfigValidation:
    """Test authentication configuration validation."""

    @pytest.mark.parametrize(
        "config_data, expected",
        [
            (
                {
                    "organization": [
                        {
                            "tenant_id": "tenant1",
                            "client_id": "client1",
                            "client_secret": "secret1",
                            "url": "https://dev.azure.com",
                            "name": "org1",
                        },
                    ],
                },
                True,
            ),
            ({}, False),
            ({"organization": []}, False),
            ({"organization": [{}]}, False),
            (
                {
                    "organization": [
                        {
                            "tenant_id": "tenant1",
                            "client_id": "client1",
                            "client_secret": "secret1",
                            "url": "http://example.com",  # Invalid URL
                            "name": "org1",
                        },
                    ],
                },
                False,
            ),
        ],
    )
    def test_validate_auth_config(self, config_data, expected):
        """Test authentication configuration validation with various inputs."""
        assert validate_auth_config(config_data) is expected


class TestSyncOrganization:
    """Test organization sync functionality."""

    @patch("cartography.intel.azuredevops.concurrent_execution")
    @patch("cartography.intel.azuredevops.projects.sync")
    @patch("cartography.intel.azuredevops.organization.sync")
    def test_sync_organization_success(
        self, mock_org_sync, mock_projects_sync, mock_concurrent_exec,
    ):
        """Test successful and complete synchronization of an organization."""
        mock_session = MagicMock()
        mock_config = MagicMock(spec=Config)
        mock_config.azure_devops_concurrent_requests = 1
        common_params = {"UPDATE_TAG": "tag", "WORKSPACE_ID": "workspace"}
        projects_data = [{"id": "proj1"}, {"id": "proj2"}]
        mock_projects_sync.return_value = projects_data

        sync_organization(
            mock_session,
            mock_config,
            "test-org",
            "https://dev.azure.com",
            "token",
            common_params,
        )

        mock_org_sync.assert_called_once()
        mock_projects_sync.assert_called_once()
        assert mock_concurrent_exec.call_count == 2


class TestStartAzureDevOpsIngestion:
    """Test the main Azure DevOps ingestion function."""

    def test_start_azure_devops_ingestion_no_config(self):
        """Test that ingestion gracefully exits when no configuration is provided."""
        mock_session = MagicMock()
        mock_config = MagicMock(spec=Config)
        mock_config.azure_devops_config = None

        start_azure_devops_ingestion(mock_session, mock_config)
        # Should return without error and without performing any actions

    @patch("cartography.intel.azuredevops.get_access_token")
    @patch("cartography.intel.azuredevops.sync_organization")
    def test_start_azure_devops_ingestion_success(self, mock_sync_org, mock_get_token):
        """Test a successful ingestion run for a single organization."""
        mock_session = MagicMock()
        mock_config = MagicMock(spec=Config)
        org_config = {
            "organization": [
                {
                    "tenant_id": "tenant1",
                    "client_id": "client1",
                    "client_secret": "secret1",
                    "url": "https://dev.azure.com",
                    "name": "org1",
                },
            ],
        }
        mock_config.azure_devops_config = base64.b64encode(
            json.dumps(org_config).encode(),
        ).decode()
        mock_config.params = {"workspace": {"id_string": "ws1", "account_id": "org1"}}
        mock_config.update_tag = "update_tag"
        mock_get_token.return_value = "access-token"

        start_azure_devops_ingestion(mock_session, mock_config)

        mock_get_token.assert_called_once_with("tenant1", "client1", "secret1")
        mock_sync_org.assert_called_once()

    @pytest.mark.parametrize(
        "config_str",
        ["aW52YWxpZC1iYXNlNjQ=", base64.b64encode(b"not-json").decode()],
    )
    def test_start_azure_devops_ingestion_invalid_config(self, config_str):
        """Test that ingestion handles invalid or malformed configuration gracefully."""
        mock_session = MagicMock()
        mock_config = MagicMock(spec=Config)
        mock_config.azure_devops_config = config_str

        # This should not raise an exception
        try:
            start_azure_devops_ingestion(mock_session, mock_config)
        except Exception as e:
            pytest.fail(f"Ingestion with invalid config raised an exception: {e}")

    @patch("cartography.intel.azuredevops.get_access_token")
    @patch("cartography.intel.azuredevops.sync_organization")
    def test_start_azure_devops_ingestion_token_failure(
        self, mock_sync_org, mock_get_token,
    ):
        """Test that ingestion continues to the next organization if one fails to get a token."""
        mock_session = MagicMock()
        mock_config = MagicMock(spec=Config)
        org_config = {
            "organization": [
                {
                    "tenant_id": "tenant1",
                    "client_id": "client1",
                    "client_secret": "secret1",
                    "url": "https://dev.azure.com",
                    "name": "org1",
                },
                {
                    "tenant_id": "tenant2",
                    "client_id": "client2",
                    "client_secret": "secret2",
                    "url": "https://dev.azure.com",
                    "name": "org2",
                },
            ],
        }
        mock_config.azure_devops_config = base64.b64encode(
            json.dumps(org_config).encode(),
        ).decode()
        mock_config.params = {"workspace": {"id_string": "ws1", "account_id": "org2"}}
        mock_config.update_tag = "update_tag"
        mock_get_token.side_effect = [None, "access-token-2"]

        start_azure_devops_ingestion(mock_session, mock_config)

        assert mock_get_token.call_count == 2
        mock_sync_org.assert_called_once()  # Only the second org should be synced
