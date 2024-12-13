import base64
import json
import logging
import time
import uuid
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import requests
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError
from azure.core.pipeline.policies import RetryPolicy
from azure.identity import AzureCliCredential
from azure.identity import ClientSecretCredential
from azure.identity import TokenCredential
from msgraph.core import GraphClient

logger = logging.getLogger(__name__)
GRAPH_ENDPOINT = "https://graph.microsoft.com/v1.0"


class GraphHeaders:
    @staticmethod
    def get_default_headers() -> Dict[str, str]:
        """
        Get default headers according to Microsoft Graph best practices
        https://learn.microsoft.com/en-us/graph/api/overview?view=graph-rest-1.0
        """
        return {
            "ConsistencyLevel": "eventual",  # For better query performance
            "Content-Type": "application/json",
            "Accept": "application/json",  # Explicitly request JSON responses
            "Prefer": 'outlook.timezone="UTC"',  # Consistent timezone handling
            "client-request-id": str(uuid.uuid4()),  # For request tracing
            "return-client-request-id": "true",
            "SdkVersion": "cartography-1.0",  # Identify your application
        }

    @staticmethod
    def get_batch_headers() -> Dict[str, str]:
        """Specific headers for batch operations"""
        headers = GraphHeaders.get_default_headers()
        headers.update(
            {
                "Content-Type": "application/json",
                "maxPayloadSize": "10",  # Limit batch size
                "Accept": "application/json",
            },
        )
        return headers


class Credentials:
    def __init__(
        self,
        arm_credentials: TokenCredential,
        graph_credentials: TokenCredential,
        vault_credentials: TokenCredential = None,
        tenant_id: str = None,
        subscription_id: str = None,
        current_user: Dict = None,
        api_version: str = "v1.0",
    ) -> None:
        self.arm_credentials = arm_credentials
        self.graph_credentials = graph_credentials
        self.vault_credentials = vault_credentials
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.current_user = current_user
        self.graph_client = GraphClient(credentials=graph_credentials)
        self.api_version = api_version
        self.graph_endpoint = f"https://graph.microsoft.com/{api_version}"

        # Configure retry policy
        retry_policy = RetryPolicy(
            retry_total=3,
            retry_on_status_codes={408, 429, 500, 502, 503, 504},
            retry_backoff_factor=2,
        )

        # Initialize Graph client with policies
        self.graph_client = GraphClient(
            credentials=graph_credentials,
            retry_policy=retry_policy,
        )

    def _get_default_headers(self) -> Dict[str, str]:
        """Get default headers including monitoring headers"""
        headers = {
            "ConsistencyLevel": "eventual",
            "Content-Type": "application/json",
            "Prefer": 'outlook.timezone="UTC"',
        }
        headers.update(GraphMonitoring.get_correlation_headers())
        return headers

    async def batch_request(self, requests: List[Dict]) -> Dict:
        """
        Execute batch operations against Microsoft Graph
        """
        try:
            # Validate batch size
            if len(requests) > 20:
                raise ValueError("Batch requests cannot exceed 20 requests per batch")

            # Add request IDs if not present
            for i, request in enumerate(requests):
                if "id" not in request:
                    request["id"] = str(i + 1)

            batch_payload = {
                "requests": requests,
                "atomicityGroup": str(uuid.uuid4()),  # Group related requests
            }

            headers = GraphHeaders.get_batch_headers()

            response = await self.graph_client.post(
                f"{self.graph_endpoint}/$batch",
                headers=headers,
                json=batch_payload,
            )

            # Process batch response
            batch_response = response.json()
            self._validate_batch_response(batch_response)
            return batch_response

        except HttpResponseError as e:
            GraphErrorHandler.handle_error(e)
            raise
        except Exception as e:
            logger.error(f"Batch request failed: {e}")
            raise

    def _validate_batch_response(self, response: Dict) -> None:
        """Validate batch response and handle errors"""
        if "responses" not in response:
            raise ValueError("Invalid batch response format")

        for resp in response["responses"]:
            if "status" in resp and resp["status"] >= 400:
                logger.error(f"Batch request {resp.get('id')} failed: {resp}")
                if resp["status"] == 429:  # Throttling
                    retry_after = resp.get("headers", {}).get("Retry-After", "60")
                    logger.warning(f"Rate limit hit, retry after {retry_after} seconds")

    def get_current_user(self) -> Optional[Dict]:
        """Get current user with error handling"""
        if not self.current_user and self.graph_client:
            try:
                headers = GraphHeaders.get_default_headers()
                response = self.graph_client.get(
                    f"{self.graph_endpoint}/me",
                    headers=headers,
                )
                self.current_user = {
                    "id": response.json().get("id"),
                    "email": response.json().get("userPrincipalName"),
                    "name": response.json().get("displayName"),
                }
            except HttpResponseError as e:
                GraphErrorHandler.handle_error(e)
            except Exception as e:
                logger.error(f"Failed to get current user: {e}")
        return self.current_user

    def get_tenant_id(self) -> Optional[str]:
        if self.tenant_id:
            return self.tenant_id

        try:
            token = self.graph_credentials.get_token(
                "https://graph.microsoft.com/.default",
            )
            payload = token.token.split(".")[1]
            decoded = json.loads(base64.b64decode(payload + "===").decode("utf-8"))
            return decoded.get("tid")
        except Exception as e:
            logger.error(f"Unable to infer tenant ID: {e}")
            return None


class ImpersonateCredentials:
    """
    Handles user impersonation for Microsoft Graph API
    Maintains compatibility with multiple Azure service endpoints
    """

    def __init__(self, cred: Dict[str, Any], resource: str) -> None:
        self.scheme = "Bearer"
        self.cred = cred
        self.resource = resource
        self.token = AccessToken(
            self.cred["access_token"],
            int(self.cred["expires_in"] + time.time()),
        )

    def get_token(self, *scopes, **kwargs) -> AccessToken:
        """Get token with validation"""
        if not self.validate_token(self.token):
            self.refresh_token()
        return self.token

    def validate_token(self, token: AccessToken) -> bool:
        """Validate token expiration"""
        if not token:
            return False
        expiration_buffer = 300  # 5 minutes
        return token.expires_on > int(time.time()) + expiration_buffer

    def signed_session(self, session=None):
        """Get authenticated session"""
        if session is None:
            session = requests.Session()
        session.headers["Authorization"] = f"{self.scheme} {self.token.token}"
        return session


class Authenticator:
    # Define scopes for different services
    GRAPH_SCOPES = {
        "default": ["https://graph.microsoft.com/.default"],
        "user": ["User.Read", "User.ReadBasic.All"],
        "directory": ["Directory.Read.All"],
    }
    VAULT_SCOPES = ["https://vault.azure.net/user_impersonation"]
    ARM_SCOPES = ["https://management.azure.com/.default"]

    def authenticate_cli(self) -> Credentials:
        try:
            self._set_logging_levels()
            cli_credential = AzureCliCredential()

            headers = GraphMonitoring.get_correlation_headers()
            return Credentials(
                arm_credentials=cli_credential,
                graph_credentials=cli_credential,
                vault_credentials=cli_credential,
                tenant_id=self._get_tenant_id(cli_credential),
                subscription_id=self._get_subscription_id(cli_credential),
            )
        except HttpResponseError as e:
            self._handle_auth_error(e)
            raise

    def authenticate_sp(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ) -> Credentials:
        try:
            self._set_logging_levels()
            credential = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
            )

            return Credentials(
                arm_credentials=credential,
                graph_credentials=credential,
                vault_credentials=credential,
                tenant_id=tenant_id,
                current_user={"client_id": client_id},
            )
        except HttpResponseError as e:
            self._handle_auth_error(e)
            raise

    def _set_logging_levels(self):
        """Helper method to set logging levels"""
        loggers = ["azure.core.pipeline.policies.http_logging_policy", "urllib3"]
        for logger_name in loggers:
            logging.getLogger(logger_name).setLevel(logging.ERROR)

    def _handle_auth_error(self, error: Exception):
        """Enhanced error handling for authentication"""
        try:
            GraphErrorHandler.handle_error(error)
        except HttpResponseError as e:
            if "AADSTS700016" in str(e):  # Application not found
                logger.error("Application not found in tenant")
            elif "AADSTS70011" in str(e):  # Invalid scope
                logger.error("Invalid scope provided")
            else:
                logger.error(f"Authentication failed: {e}")
            raise

    def _get_tenant_id(self, credential: TokenCredential) -> Optional[str]:
        try:
            token = credential.get_token("https://graph.microsoft.com/.default")
            payload = token.token.split(".")[1]
            decoded = json.loads(base64.b64decode(payload + "===").decode("utf-8"))
            return decoded.get("tid")
        except Exception as e:
            logger.error(f"Failed to get tenant ID: {e}")
            return None

    def _get_subscription_id(self, credential: TokenCredential) -> Optional[str]:
        try:
            token = credential.get_token("https://management.azure.com/.default")
            # Make a request to Azure Management API to get subscription ID
            headers = {"Authorization": f"Bearer {token.token}"}
            response = requests.get(
                "https://management.azure.com/subscriptions?api-version=2020-01-01",
                headers=headers,
            )
            return response.json()["value"][0]["subscriptionId"]
        except Exception as e:
            logger.error(f"Failed to get subscription ID: {e}")
            return None

    def validate_token(self, token: AccessToken) -> bool:
        """Validate token before use"""
        if not token:
            return False

        # Check expiration with 5-minute buffer
        expiration_buffer = 300  # 5 minutes
        return token.expires_on > int(time.time()) + expiration_buffer

    def impersonate_user(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        refresh_token: str,
        graph_scope: str,
        default_graph_scope: str,
        azure_scope: str,
        vault_scope: str,
        subscription_id: str,
        tenant_id: str = None,
    ) -> Credentials:
        """
        Implements user impersonation for Microsoft Graph API
        """
        try:
            self._set_logging_levels()

            # Get tokens for different services
            graph_creds = self._get_service_token(
                client_id,
                client_secret,
                redirect_uri,
                refresh_token,
                graph_scope,
                tenant_id,
                "graph",
            )

            vault_creds = self._get_service_token(
                client_id,
                client_secret,
                redirect_uri,
                refresh_token,
                vault_scope,
                tenant_id,
                "vault",
            )

            azure_creds = self._get_service_token(
                client_id,
                client_secret,
                redirect_uri,
                refresh_token,
                azure_scope,
                tenant_id,
                "management",
            )

            # Get user context from token
            user_tenant_id, user = self._decode_token(azure_creds.token.token)
            tenant_id = tenant_id or user_tenant_id

            return Credentials(
                arm_credentials=azure_creds,
                graph_credentials=graph_creds,
                vault_credentials=vault_creds,
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                current_user=user,
            )

        except Exception as e:
            logger.error(f"Failed to impersonate user: {e}", exc_info=True)
            raise

    def _get_service_token(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        refresh_token: str,
        scope: str,
        tenant_id: str,
        resource: str,
    ) -> ImpersonateCredentials:
        """Get token for specific Azure service"""
        token_endpoint = f"https://login.microsoftonline.com/{tenant_id or 'common'}/oauth2/v2.0/token"

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            **GraphHeaders.get_default_headers(),
        }

        data = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "redirect_uri": redirect_uri,
            "scope": scope,
        }

        try:
            response = requests.post(token_endpoint, headers=headers, data=data)
            response.raise_for_status()
            return ImpersonateCredentials(response.json(), resource)
        except HttpResponseError as e:
            GraphErrorHandler.handle_error(e)
            raise
        except Exception as e:
            logger.error(f"Token acquisition failed: {e}")
            raise

    def _decode_token(self, token: str) -> Tuple[str, Dict[str, str]]:
        """Decode JWT token and extract user information"""
        try:
            payload = token.split(".")[1]
            decoded = json.loads(base64.b64decode(payload + "===").decode("utf-8"))

            return decoded.get("tid"), {
                "id": decoded.get("oid"),
                "name": decoded.get("name"),
                "email": decoded.get("preferred_username"),
                "roles": decoded.get("roles", []),
            }
        except Exception as e:
            logger.error(f"Token decode failed: {e}")
            raise


class GraphErrorHandler:
    @staticmethod
    def handle_error(error: HttpResponseError) -> None:
        """Handle Microsoft Graph specific errors"""
        if not isinstance(error, HttpResponseError):
            return

        error_code = error.status_code
        error_message = str(error)

        if error_code == 429:  # Throttling
            retry_after = error.response.headers.get("Retry-After", "60")
            logger.warning(f"Rate limit hit, retry after {retry_after} seconds")
        elif error_code == 401:
            logger.error("Authentication failed: Token expired or invalid")
        elif error_code == 403:
            logger.error("Authorization failed: Insufficient permissions")
        elif error_code == 404:
            logger.error(f"Resource not found: {error_message}")
        else:
            logger.error(f"Graph API error: {error_code} - {error_message}")

        raise error


class GraphMonitoring:
    @staticmethod
    def get_correlation_headers() -> Dict[str, str]:
        """Generate correlation headers for request tracking"""
        return {
            "client-request-id": str(uuid.uuid4()),
            "return-client-request-id": "true",
        }
