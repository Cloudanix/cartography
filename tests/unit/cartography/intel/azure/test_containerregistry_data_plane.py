"""
Drive the real azure-containerregistry client through a fake HTTP transport: proves the module
talks to the registry data plane with the right paths and parameters, survives the ACR token
challenge, and shows how many HTTP requests one repository costs.
"""
import base64
import json
import sys
import time
from typing import Any
from typing import Dict
from typing import List
from unittest.mock import MagicMock
from unittest.mock import patch
from urllib.parse import parse_qs
from urllib.parse import urlparse

import pytest
import requests
from azure.core.credentials import AccessToken
from azure.core.pipeline.transport import HttpTransport
from azure.core.pipeline.transport import RequestsTransportResponse

from cartography.intel.azure import containerregistry
from tests.data.azure.containerregistry import REGISTRY

pytestmark = pytest.mark.skipif(
    isinstance(sys.modules.get('azure.containerregistry'), MagicMock),
    reason='azure-containerregistry is not installed (mocked by conftest)',
)

ACCESS_TOKEN = 'acr-access-token'
CHALLENGE = (
    'Bearer realm="https://myregistry.azurecr.io/oauth2/token",service="myregistry.azurecr.io",'
    'scope="repository:webapp:metadata_read"'
)
MANIFEST = {
    'digest': 'sha256:{}', 'imageSize': 1024, 'createdTime': '2026-10-01T00:00:00Z',
    'lastUpdateTime': '2026-10-02T00:00:00Z', 'architecture': 'amd64', 'os': 'linux', 'tags': ['v1'],
}


def _refresh_token() -> str:
    payload = base64.urlsafe_b64encode(json.dumps({'exp': int(time.time()) + 3600}).encode()).decode().rstrip('=')
    return f'e30.{payload}.sig'


class FakeCredential:
    def __init__(self):
        self.scopes: List[str] = []

    def get_token(self, *scopes, **kwargs):
        self.scopes.extend(scopes)
        return AccessToken('aad-token', int(time.time()) + 3600)


class FakeRegistry(HttpTransport):
    """Answers like an ACR registry: 401 + challenge until the request carries an ACR access token."""

    def __init__(self, repositories: List[str], data_status: int = 200):
        self.repositories = repositories
        self.data_status = data_status
        self.requests: List = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def open(self):
        pass

    def close(self):
        pass

    def send(self, request, **kwargs):
        # Snapshot: the SDK mutates the same request object when it retries with a token.
        self.requests.append((urlparse(request.url), request.headers.get("Authorization")))
        status, headers, body = self._route(request)
        response = requests.Response()
        response.status_code = status
        response.headers.update({'Content-Type': 'application/json', **headers})
        response._content = json.dumps(body).encode()
        response.url = request.url
        return RequestsTransportResponse(request, response)

    def _route(self, request):
        url = urlparse(request.url)
        if url.path == '/oauth2/exchange':
            return 200, {}, {'refresh_token': _refresh_token()}
        if url.path == '/oauth2/token':
            return 200, {}, {'access_token': ACCESS_TOKEN}
        if request.headers.get('Authorization') != f'Bearer {ACCESS_TOKEN}':
            return 401, {'WWW-Authenticate': CHALLENGE}, {'errors': [{'code': 'UNAUTHORIZED'}]}
        if self.data_status != 200:
            return self.data_status, {}, {'errors': [{'code': 'DENIED', 'message': 'client is not allowed access'}]}
        if url.path == '/acr/v1/_catalog':
            return 200, {}, {'repositories': self.repositories}
        name = url.path.split('/')[3]
        manifests = [{**MANIFEST, 'digest': f'sha256:{name}{i}'} for i in range(3)]
        return 200, {}, {'registry': 'myregistry.azurecr.io', 'imageName': name, 'manifests': manifests}


def _sync(transport: FakeRegistry, credential: Any) -> Dict[str, Any]:
    from azure.containerregistry import ContainerRegistryClient
    real_init = ContainerRegistryClient.__init__

    def init_with_fake_transport(self, *args, **kwargs):
        real_init(self, *args, transport=transport, **kwargs)

    with patch.object(ContainerRegistryClient, '__init__', init_with_fake_transport), \
            patch.object(containerregistry, 'load_repositories') as load_repositories, \
            patch.object(containerregistry, 'load_images') as load_images, \
            patch.object(containerregistry, 'load_registry_fetch_status') as load_status:
        containerregistry.sync_registry_contents(MagicMock(), credential, REGISTRY, 7)
    return {
        'repositories': [r for call in load_repositories.call_args_list for r in call.args[-2]],
        'images': [i for call in load_images.call_args_list for i in call.args[-2]],
        'status': load_status.call_args.args[-1],
    }


def test_real_sdk_lists_repositories_and_manifests_through_the_data_plane():
    transport, credential = FakeRegistry(['webapp', 'api-service']), FakeCredential()

    loaded = _sync(transport, credential)

    assert [r['name'] for r in loaded['repositories']] == ['webapp', 'api-service']
    assert len(loaded['images']) == 6
    assert loaded['images'][0]['id'].endswith('/repositories/webapp@sha256:webapp0')
    assert loaded['status']['repositories_fetched'] is True
    assert credential.scopes and set(credential.scopes) == {'https://containerregistry.azure.net/.default'}

    data_calls = [url for url, auth in transport.requests if auth == f'Bearer {ACCESS_TOKEN}']
    paths = [url.path for url in data_calls]
    assert paths == ['/acr/v1/_catalog', '/acr/v1/webapp/_manifests', '/acr/v1/api-service/_manifests']
    manifest_query = parse_qs(data_calls[1].query)
    assert manifest_query['orderby'] == ['timedesc']
    # Every data-plane call costs 4 HTTP requests with this SDK: 401 challenge, AAD->ACR refresh
    # token exchange, refresh->access token exchange, and the authorized retry.
    assert len(transport.requests) == 4 * len(data_calls)


def test_real_sdk_forbidden_registry_is_skipped():
    transport = FakeRegistry(['webapp'], data_status=403)

    loaded = _sync(transport, FakeCredential())

    assert loaded['repositories'] == []
    assert loaded['status']['repositories_fetched'] is False
    assert loaded['status']['repositories_fetch_error'] == 'http_403'
