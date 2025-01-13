import base64
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict , Optional


import requests
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError
from azure.identity import ClientSecretCredential, AzureCliCredential
import msal
from msal.exceptions import MsalServiceError, MsalClientError

logger = logging.getLogger(__name__)
AUTHORITY_HOST_URI = 'https://login.microsoftonline.com'
MANAGEMENT_SCOPE = 'https://management.azure.com/.default'
MS_GRAPH_SCOPE = 'https://graph.microsoft.com/.default'
VAULT_SCOPE = 'https://vault.azure.net/.default'


class Credentials:

    def __init__(
        self, arm_credentials: Any, aad_graph_credentials: Any, default_graph_credentials: Any, 
        vault_credentials: Any, tenant_id: str = None, subscription_id: str = None, 
        msal_app: msal.ClientApplication = None, current_user: Dict = None,
    ) -> None:
        self.arm_credentials = arm_credentials  # Azure Resource Manager API credentials
        self.aad_graph_credentials = aad_graph_credentials  # AAD Graph API credentials
        self.default_graph_credentials = default_graph_credentials  # Microsoft Graph API credentials
        self.vault_credentials = vault_credentials  # Azure vault API credentials
        self.tenant_id = tenant_id
        self.subscription_id = subscription_id
        self.msal_app = msal_app
        self.current_user = current_user
        self._token_cache = {}

    def get_current_user(self) -> Optional[str]:
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
        if not hasattr(credentials, 'token'):
            return credentials

        try:
            # Validate token format
            if not credentials.token.get('access_token'):
                logger.debug('Invalid token format - missing access_token')
                return self.refresh_credential(credentials)

            # Check expiration
            expires_on = credentials.token.get('expires_on') or credentials.token.get('expires_at', 0)
            expiration_datetime = datetime.fromtimestamp(int(expires_on))
            
            if datetime.now() + timedelta(minutes=5) >= expiration_datetime:
                return self.refresh_credential(credentials)
            
            return credentials
        except (ValueError, TypeError) as e:
            logger.error(f"Token validation error: {str(e)}")
            return self.refresh_credential(credentials)

    def refresh_credential(self, credentials: Any) -> Any:
        """
        Refresh credentials using MSAL
        """
        if not self.msal_app:
            return credentials

        logger.debug('Refreshing credentials using MSAL')
        
        try:
            # Get original token parameters
            resource = credentials.token.get('resource')
            user_id = credentials.token.get('user_id')
            
            if not resource:
                logger.error("No resource found in token")
                return credentials
            
            # Convert resource to scope (MSAL requirement)
            scope = f"{resource}/.default"
            
            # First try to acquire token silently if we have user context
            result = None
            if user_id:
                accounts = self.msal_app.get_accounts(username=user_id)
                if accounts:
                    result = self.msal_app.acquire_token_silent(
                        scopes=[scope],
                        account=accounts[0]
                    )
            
            if 'refresh_token' in credentials.token:
                result = self.msal_app.client.obtain_token_by_refresh_token(
                    credentials.token['refresh_token'],
                    scopes=[scope]
                )
            else:
                # Otherwise use client credentials flow
                result = self.msal_app.acquire_token_for_client(scopes=[scope])
            
            if not result or 'error' in result:
                logger.error(f"Token acquisition failed: {result.get('error_description') if result else 'No result'}")
                return credentials

            # Format token with required fields
            new_token = {
                'access_token': result['access_token'],
                'resource': scope.split('/.default')[0],  # Extract resource from scope
                'token_type': result.get('token_type', 'Bearer'),
                'expires_on': int(time.time() + result['expires_in']),
                '_client_id': credentials.token.get('_client_id'),
                'user_id': credentials.token.get('user_id')
            }
            
            return type(credentials)(new_token)

        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            return credentials


class ImpersonateCredentials:
    def __init__(self, cred: Credentials, resource: str) -> None:
        self.scheme = "Bearer"
        self.cred = cred
        self.resource = resource

    def get_token(self, *scopes, **kwargs):  # pylint:disable=unused-argument
        return AccessToken(self.cred['access_token'], int(self.cred['expires_in'] + time.time()))

    def signed_session(self, session=None):
        header = "{} {}".format(self.scheme, self.cred['access_token'])
        session.headers['Authorization'] = header
        return session


class Authenticator:

    def authenticate_cli(self) -> Credentials:
        """
        Implements authentication for the Azure provider using CLI
        """
        try:
            # Set logging level to error for libraries
            logging.getLogger('msal').setLevel(logging.ERROR)
            logging.getLogger('msrest').setLevel(logging.ERROR)
            logging.getLogger('urllib3').setLevel(logging.ERROR)
            logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)

            cli_credential = AzureCliCredential()
            
            # Get ARM token for tenant discovery
            arm_token = cli_credential.get_token(MANAGEMENT_SCOPE)
            
            # Get tenant and subscription info
            headers = {'Authorization': f'Bearer {arm_token.token}'}
            r = requests.get('https://management.azure.com/tenants?api-version=2020-01-01', headers=headers)
            tenant_info = r.json()
            tenant_id = tenant_info['value'][0]['tenantId']
            
            # Get subscription info from ARM token
            subscription_id = None
            try:
                r = requests.get(
                    'https://management.azure.com/subscriptions?api-version=2020-01-01',
                    headers=headers
                )
                subs = r.json()
                if subs.get('value'):
                    subscription_id = subs['value'][0]['subscriptionId']
            except Exception as e:
                logger.warning(f"Could not get subscription ID: {e}")

            # Create graph credentials using the same CLI credential
            graph_credential = cli_credential  # Will request graph scope when needed

            return Credentials(
                arm_credentials=cli_credential,
                default_graph_creds=graph_credential,
                vault_credentials=None,
                tenant_id=tenant_id,
                subscription_id=subscription_id,
                current_user=self._get_current_user_info(arm_token.token)
            )

        except HttpResponseError as e:
            logger.error(f'Authentication failed: {e}')
            raise e

    def authenticate_sp(
            self,
            tenant_id: str,
            client_id: str,
            client_secret: str,
    ) -> Credentials:
        """
        Implements service principal authentication using MSAL
        """
        try:
            # Configure logging
            for logger_name in ['msal', 'msrest', 'urllib3', 'azure.core.pipeline.policies.http_logging_policy']:
                logging.getLogger(logger_name).setLevel(logging.ERROR)

            # Initialize MSAL application with proper configuration
            authority = f"{AUTHORITY_HOST_URI}/{tenant_id}"
            msal_app = msal.ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=authority,
                token_cache=msal.SerializableTokenCache()  # Add token cache
            )

            # Acquire initial tokens with retry logic
            arm_result = self._acquire_token_with_retry(msal_app, MANAGEMENT_SCOPE)
            graph_result = self._acquire_token_with_retry(msal_app, MS_GRAPH_SCOPE)

            if not arm_result or not graph_result:
                raise Exception("Failed to acquire initial tokens")

            # Create credentials using Azure Identity library
            arm_credentials = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )
            
            graph_credentials = ClientSecretCredential(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret
            )

            return Credentials(
                arm_credentials=arm_credentials,
                aad_graph_credentials=None,  # Maintained for compatibility
                default_graph_credentials=graph_credentials,
                vault_credentials=None,
                tenant_id=tenant_id,
                msal_app=msal_app,
                current_user={'client_id': client_id}
            )

        except Exception as e:
            logger.error(f'Authentication failed: {str(e)}')
            raise

    def _acquire_token_with_retry(self, msal_app: msal.ConfidentialClientApplication, scope: str, max_retries: int = 3) -> Optional[Dict]:
        """
        Helper method to acquire tokens with retry logic
        """
        for attempt in range(max_retries):
            try:
                result = msal_app.acquire_token_for_client(scopes=[scope])
                if result and 'access_token' in result:
                    return result
                logger.warning(f"Token acquisition attempt {attempt + 1} failed")
                time.sleep(1 * (attempt + 1))  # Exponential backoff
            except Exception as e:
                logger.error(f"Token acquisition error on attempt {attempt + 1}: {str(e)}")
                if attempt == max_retries - 1:
                    raise
        return None

    def get_current_user_info(self, access_token: str) -> Dict:
        """Extract user info from JWT access token"""
        try:
            # Split token and get payload
            token_parts = access_token.split('.')
            if len(token_parts) != 3:
                return {}
            
            # Decode payload
            payload = base64.b64decode(token_parts[1] + '=' * (-len(token_parts[1]) % 4))
            claims = json.loads(payload)
            
            return {
                'email': claims.get('upn', claims.get('email', '')),
                'name': claims.get('name', ''),
                'id': claims.get('oid', '')
            }
        except Exception as e:
            logger.warning(f"Failed to extract user info from token: {e}")
            return {}

    # vault_scope: https://vault.azure.net/user_impersonation
    # default_graph_scope: https://graph.microsoft.com/.default
    def impersonate_user(self, client_id: str, client_secret: str, redirect_uri: str, refresh_token: str, graph_scope: str, default_graph_scope: str, azure_scope: str, vault_scope: str, subscription_id: str, tenant_id: str = None):
        """
        Implements Impersonation authentication for the Azure provider
        """
        # Use Microsoft Graph scope as default
        if not default_graph_scope:
            default_graph_scope = MS_GRAPH_SCOPE

        # Set logging level to error for libraries as otherwise generates a lot of warnings
        logging.getLogger('adal-python').setLevel(logging.ERROR)
        logging.getLogger('msrest').setLevel(logging.ERROR)
        logging.getLogger('msrestazure.azure_active_directory').setLevel(logging.ERROR)
        logging.getLogger('urllib3').setLevel(logging.ERROR)
        logging.getLogger('azure.core.pipeline.policies.http_logging_policy').setLevel(logging.ERROR)

        try:
            default_graph_creds = self.refresh_default_graph_token(client_id, client_secret, redirect_uri, refresh_token, default_graph_scope, tenant_id)
            vault_creds = self.refresh_vault_token(client_id, client_secret, redirect_uri, refresh_token, vault_scope, tenant_id)
            azure_creds = self.refresh_azure_token(client_id, client_secret, redirect_uri, refresh_token, azure_scope, tenant_id)
            user_tenant_id, user = self.decode_jwt(azure_creds.cred['id_token'])

            if tenant_id is None:
                tenant_id = user_tenant_id

            return Credentials(
                arm_credentials=azure_creds,
                aad_graph_credentials=None,
                default_graph_creds=default_graph_creds,
                vault_credentials=vault_creds,
                subscription_id=subscription_id,
                tenant_id=tenant_id,
                current_user=user
            )

        except Exception as e:
            logging.error(f"failed to impersonate user: {e}", exc_info=True, stack_info=True)

            raise Exception(e)

    def refresh_graph_token(self, client_id: str, client_secret: str, redirect_uri: str, refresh_token: str, scope: str, tenant_id: str = None) -> ImpersonateCredentials:
        return ImpersonateCredentials(self.get_access_token(client_id, client_secret, redirect_uri, refresh_token, scope, tenant_id), "graph")

    def refresh_default_graph_token(self, client_id: str, client_secret: str, redirect_uri: str, refresh_token: str, scope: str, tenant_id: str = None) -> ImpersonateCredentials:
        return ImpersonateCredentials(self.get_access_token(client_id, client_secret, redirect_uri, refresh_token, scope, tenant_id), "default_graph")

    def refresh_vault_token(self, client_id: str, client_secret: str, redirect_uri: str, refresh_token: str, scope: str, tenant_id: str = None):
        return ImpersonateCredentials(self.get_access_token(client_id, client_secret, redirect_uri, refresh_token, scope, tenant_id), "vault")

    def refresh_azure_token(self, client_id: str, client_secret: str, redirect_uri: str, refresh_token: str, scope: str, tenant_id: str = None) -> ImpersonateCredentials:
        return ImpersonateCredentials(self.get_access_token(client_id, client_secret, redirect_uri, refresh_token, scope, tenant_id), "management")

    def get_access_token(self, client_id: str, client_secret: str, redirect_uri: str, refresh_token: str, scope: str, tenant_id: str = None) -> Dict:
        token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"

        if tenant_id:
            token_url = token_url.replace("common", f"{tenant_id}")

        grant_type = "refresh_token"
        content_type = "application/x-www-form-urlencoded"
        headers = {"Content-Type": content_type}

        pload = f'grant_type={grant_type}&scope={scope}&client_id={client_id}&client_secret={client_secret}&redirect_uri={redirect_uri}&refresh_token={refresh_token}'
        r = requests.post(token_url, data=pload, headers=headers)

        return r.json()

    def decode_jwt(self, id_token: str) -> Dict:
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
