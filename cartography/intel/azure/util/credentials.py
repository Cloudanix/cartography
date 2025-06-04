import base64
import json
import logging
import time
from datetime import datetime
from datetime import timedelta
from typing import Any
from typing import Dict
from typing import Optional
from typing import Tuple

import msal
import requests
from azure.common.credentials import get_azure_cli_credentials
from azure.common.credentials import get_cli_profile
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError
from azure.identity import ClientSecretCredential

logger = logging.getLogger(__name__)
AUTHORITY_HOST_URI = 'https://login.microsoftonline.com'
MS_GRAPH_SCOPE = 'https://graph.microsoft.com/.default'


class Credentials:
    def __init__(
        self,
        arm_credentials: Any,
        default_graph_creds: Any,
        vault_credentials: Any,
        tenant_id: Optional[str] = None,
        subscription_id: Optional[str] = None,
        app: Optional[msal.ClientApplication] = None,
        current_user: Optional[Dict[Any, Any]] = None,
    ) -> None:
        self.arm_credentials = arm_credentials  # Azure Resource Manager API credentials
        self.default_graph_credentials = default_graph_creds  # Azure Default Graph API credentials
        # Alias for backward compatibility
        self.aad_graph_credentials = self.default_graph_credentials  # Alias for backward compatibility
        self.vault_credentials = vault_credentials  # Azure vault API credentials
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.app = app
        self.current_user = current_user

    def get_current_user(self) -> Optional[Dict[Any, Any]]:
        return self.current_user

    def get_tenant_id(self) -> Any:
        if self.tenant_id:
            return self.tenant_id
        elif hasattr(self.default_graph_credentials, 'token') and 'tenant_id' in self.default_graph_credentials.token:
            return self.default_graph_credentials.token['tenant_id']
        else:
            # This is a last resort, e.g. for MSI authentication
            try:
                h = {'Authorization': 'Bearer {}'.format(self.arm_credentials.token['access_token'])}
                r = requests.get('https://management.azure.com/tenants?api-version=2020-01-01', headers=h)
                r2 = r.json()
                return r2.get('value')[0].get('tenantId')
            except requests.ConnectionError as e:
                logger.error(f'Unable to infer tenant ID: {e}')
                return None

    def get_credentials(self, resource: str) -> Any:
        if resource == 'arm':
            self.arm_credentials = self.get_fresh_credentials(self.arm_credentials)
            return self.arm_credentials
        elif resource == 'graph':
            self.default_graph_credentials = self.get_fresh_credentials(self.default_graph_credentials)
            return self.default_graph_credentials
        else:
            raise Exception('Invalid credentials resource type')

    def get_fresh_credentials(self, credentials: Any) -> Any:
        """
        Check if credentials are outdated and if so refresh them.
        """
        if self.app and hasattr(credentials, 'token'):
            expiration_datetime = datetime.fromtimestamp(int(credentials.token['expires_on']))
            current_datetime = datetime.now()
            expiration_delta = expiration_datetime - current_datetime
            if expiration_delta < timedelta(minutes=5):
                return self.refresh_credential(credentials)
        return credentials

    def refresh_credential(self, credentials: Any) -> Any:
        """
        Refresh credentials
        """
        logger.debug('Refreshing credentials')

        if not self.app:
            logger.error("MSAL application context not available")
            return credentials

        # Use MSAL's acquire_token_silent to refresh the token
        accounts = self.app.get_accounts()
        if not accounts:
            logger.warning("No accounts found in token cache, returning existing credentials")
            return credentials

        account = accounts[0]
        scopes = [credentials.token['scope']] if 'scope' in credentials.token else [MS_GRAPH_SCOPE]

        result = self.app.acquire_token_silent(
            scopes=scopes,
            account=account,
        )

        if not result:
            logger.warning("Failed to refresh token, returning existing credentials")
            return credentials

        return ImpersonateCredentials(result, credentials.token.get('resource', 'graph'))


class ImpersonateCredentials:
    def __init__(self, cred: Dict[str, Any], resource: str) -> None:
        self.scheme = "Bearer"
        self.cred = cred
        self.resource = resource

        if 'expires_on' not in self.cred and 'expires_in' in self.cred:
            self.cred['expires_on'] = int(time.time() + int(self.cred['expires_in']))

    def get_token(self, *scopes: str, **kwargs: Any) -> AccessToken:  # pylint:disable=unused-argument
        return AccessToken(self.cred['access_token'], int(self.cred['expires_on']))

    def signed_session(self, session: Optional[requests.Session] = None) -> requests.Session:
        if session is None:
            session = requests.Session()
        header = "{} {}".format(self.scheme, self.cred['access_token'])
        session.headers['Authorization'] = header
        return session


class Authenticator:

    def authenticate_cli(self) -> Credentials:
        """
        Implements authentication for the Azure provider
        """
        try:
            # Set logging level to error for libraries
            logging.getLogger('msal').setLevel(logging.ERROR)
            logging.getLogger('msrest').setLevel(logging.ERROR)
            logging.getLogger('urllib3').setLevel(logging.ERROR)
            logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)

            arm_credentials, subscription_id, tenant_id = get_azure_cli_credentials(with_tenant=True)
            default_graph_credentials, _, _ = get_azure_cli_credentials(
                with_tenant=True,
                resource=MS_GRAPH_SCOPE,
            )

            profile = get_cli_profile()
            current_user = {'email': profile.get_current_account_user()}

            return Credentials(
                arm_credentials=arm_credentials,
                default_graph_creds=default_graph_credentials,
                vault_credentials=None,  # Vault credentials can be added if needed
                tenant_id=tenant_id,
                current_user=current_user,
                subscription_id=subscription_id,
            )

        except HttpResponseError as e:
            logger.error(f'Authentication failed: {e}')
            raise e

    def authenticate_sp(
            self,
            tenant_id: Optional[str] = None,
            client_id: Optional[str] = None,
            client_secret: Optional[str] = None,
    ) -> Credentials:
        """
        Implements authentication for the Azure provider
        """
        try:
            # Set logging level to error for libraries
            logging.getLogger('msal').setLevel(logging.ERROR)
            logging.getLogger('msrest').setLevel(logging.ERROR)
            logging.getLogger('urllib3').setLevel(logging.ERROR)
            logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)

            arm_credentials = ClientSecretCredential(
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=tenant_id,
            )

            default_graph_credentials = ClientSecretCredential(
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=tenant_id,
            )

            current_user = {'id': client_id} if client_id else None

            return Credentials(
                arm_credentials=arm_credentials,
                default_graph_creds=default_graph_credentials,
                vault_credentials=None,
                tenant_id=tenant_id,
                current_user=current_user,
            )

        except HttpResponseError as e:
            logger.error(f'Service Principal authentication failed: {e}')
            raise e

    def impersonate_user(
            self,
            client_id: str,
            client_secret: str,
            redirect_uri: str,
            refresh_token: str,
            graph_scope: str,
            azure_scope: str,
            vault_scope: str,
            subscription_id: str,
            tenant_id: Optional[str] = None,
    ) -> Credentials:
        """
        Implements Impersonation authentication for the Azure provider using MSAL
        """
        # Set logging level to error for libraries
        logging.getLogger('msal').setLevel(logging.ERROR)
        logging.getLogger('msrest').setLevel(logging.ERROR)
        logging.getLogger('urllib3').setLevel(logging.ERROR)
        logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)

        try:
            authority = f"{AUTHORITY_HOST_URI}/{'common' if not tenant_id else tenant_id}"

            app = msal.ConfidentialClientApplication(
                client_id=client_id,
                authority=authority,
                client_credential=client_secret,
            )

            default_graph_creds = self.refresh_graph_token(app, refresh_token, graph_scope)
            vault_creds = self.refresh_vault_token(app, refresh_token, vault_scope)
            azure_creds = self.refresh_azure_token(app, refresh_token, azure_scope)

            user_tenant_id, user = self.decode_jwt(azure_creds.cred['id_token'])

            if tenant_id is None:
                tenant_id = user_tenant_id

            return Credentials(
                arm_credentials=azure_creds,
                default_graph_creds=default_graph_creds,
                vault_credentials=vault_creds,
                subscription_id=subscription_id,
                tenant_id=tenant_id,
                current_user=user,
                app=app,
            )

        except Exception as e:
            logging.error(f"failed to impersonate user: {e}", exc_info=True, stack_info=True)

            raise Exception(e)

    def refresh_graph_token(self, app: msal.ConfidentialClientApplication, refresh_token: str, scope: str) -> ImpersonateCredentials:
        result = self.get_access_token(app, refresh_token, scope)
        return ImpersonateCredentials(result, "graph")

    def refresh_vault_token(self, app: msal.ConfidentialClientApplication, refresh_token: str, scope: str) -> ImpersonateCredentials:
        result = self.get_access_token(app, refresh_token, scope)
        return ImpersonateCredentials(result, "vault")

    def refresh_azure_token(self, app: msal.ConfidentialClientApplication, refresh_token: str, scope: str) -> ImpersonateCredentials:
        result = self.get_access_token(app, refresh_token, scope)
        return ImpersonateCredentials(result, "management")

    def get_access_token(
        self,
        app: msal.ConfidentialClientApplication,
        refresh_token: str,
        scope: str,
    ) -> Dict[str, Any]:
        """
        Helper method to acquire token using refresh token with MSAL
        """
        result = app.acquire_token_by_refresh_token(
            refresh_token=refresh_token,
            scopes=[scope],
        )

        if "error" in result:
            logger.error(f"Error acquiring token: {result.get('error_description')}")
            # Return an empty dict that has the minimum required structure
            return {"access_token": "", "expires_on": int(time.time()) + 3600}

        return result

    def decode_jwt(self, id_token: str) -> Tuple[str, Dict[str, Any]]:
        """
        Decode the JWT token to extract user information
        """
        payload = id_token.split('.')[1]

        # Standard Base64 Decoding
        decodedBytes = base64.b64decode(payload + '===')
        decodedStr = str(decodedBytes.decode('utf-8'))

        # print(decodedStr)

        decoded = json.loads(decodedStr)
        # print('tenant id', decoded['tid'])
        # print('user id', decoded['oid'])
        # print('name', decoded['name'])
        # print('email', decoded['preferred_username'])

        return decoded['tid'], {
            'id': decoded['oid'],
            'name': decoded['name'],
            'email': decoded['preferred_username'],
        }
