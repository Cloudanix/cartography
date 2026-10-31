import logging
from unittest.mock import MagicMock
from unittest.mock import Mock
from unittest.mock import patch

from azure.core.exceptions import ClientAuthenticationError
from azure.core.exceptions import HttpResponseError
from azure.core.exceptions import ServiceRequestError

from cartography.intel.azure import containerregistry
from cartography.intel.azure.containerregistry import get_image_list
from cartography.intel.azure.containerregistry import get_registry_list
from cartography.intel.azure.containerregistry import get_repository_list
from cartography.intel.azure.containerregistry import sync
from cartography.intel.azure.containerregistry import sync_registry_contents
from tests.data.azure.containerregistry import CONTAINER_REGISTRIES
from tests.data.azure.containerregistry import MANIFESTS
from tests.data.azure.containerregistry import REGISTRY
from tests.data.azure.containerregistry import REGISTRY_ID
from tests.data.azure.containerregistry import REPOSITORY_NAMES

MODULE = 'cartography.intel.azure.containerregistry'


def _http_error(status_code, cls=HttpResponseError):
    error = cls(message=f'status {status_code}')
    error.status_code = status_code
    return error


def _client(repository_names=REPOSITORY_NAMES, manifests=MANIFESTS):
    client = MagicMock()
    client.list_repository_names.return_value = iter(repository_names)
    client.list_manifest_properties.side_effect = lambda name, **kwargs: iter(manifests)
    return client


@patch(f'{MODULE}.get_client')
def test_get_registry_list(mock_get_client):
    mock_get_client.return_value.registries.list.return_value = CONTAINER_REGISTRIES

    result = get_registry_list(Mock(), 'sub-123', ['eastus', 'westus2'], {})

    assert [r['name'] for r in result] == ['myregistry', 'testregistry']
    assert result[0]['login_server'] == 'myregistry.azurecr.io'
    assert result[0]['resource_group'] == 'rg-acr'
    assert result[0]['sku_name'] == 'Premium'
    assert result[0]['admin_user_enabled'] is True
    assert result[1]['public_network_access'] == 'Disabled'


def test_get_registry_client_targets_the_registry_data_plane():
    credentials = Mock()
    with patch('azure.containerregistry.ContainerRegistryClient') as client_cls:
        containerregistry.get_registry_client(credentials, 'myregistry.azurecr.io')

    args, kwargs = client_cls.call_args
    assert args[:2] == ('https://myregistry.azurecr.io', credentials)
    assert kwargs['audience'] == 'https://containerregistry.azure.net'


def test_get_repository_list_reads_the_catalog():
    client = _client()

    result = get_repository_list(client, REGISTRY)

    client.list_repository_names.assert_called_once_with(results_per_page=100)
    assert [r['name'] for r in result] == REPOSITORY_NAMES
    assert result[0]['id'] == f'{REGISTRY_ID}/repositories/webapp'
    assert result[0]['registry_id'] == REGISTRY_ID
    assert result[0]['uri'] == 'myregistry.azurecr.io/webapp'
    assert result[0]['location'] == 'eastus'
    assert result[0]['subscription_id'] == 'sub-123'
    assert result[0]['console_link'] == REGISTRY['console_link']


def test_get_image_list_reads_manifests_newest_first():
    client = _client()
    repository = get_repository_list(client, REGISTRY)[0]

    result = get_image_list(client, repository)

    assert client.list_manifest_properties.call_args.args == ('webapp',)
    assert client.list_manifest_properties.call_args.kwargs['order_by'] == 'timedesc'
    assert [i['digest'] for i in result] == ['sha256:abc123def456', 'sha256:def456ghi789']
    assert result[0]['id'] == f'{REGISTRY_ID}/repositories/webapp@sha256:abc123def456'
    assert result[0]['repository_id'] == repository['id']
    assert result[0]['uri'] == 'myregistry.azurecr.io/webapp@sha256:abc123def456'
    assert result[0]['architecture'] == 'amd64'
    assert result[0]['os'] == 'linux'
    assert result[0]['size_bytes'] == 134217728
    assert result[0]['tags'] == ['latest', 'v1.2.3', 'stable']
    assert result[0]['created_time'] == '2021-10-15T16:30:00+00:00'
    assert result[1]['tags'] == []


@patch(f'{MODULE}.load_registry_fetch_status')
@patch(f'{MODULE}.load_images')
@patch(f'{MODULE}.load_repositories')
@patch(f'{MODULE}.get_registry_client')
def test_sync_registry_contents_loads_repositories_and_images(get_client, load_repos, load_images, load_status):
    client = _client()
    get_client.return_value = client

    sync_registry_contents(Mock(), Mock(), REGISTRY, 7)

    assert get_client.call_args.args[1] == 'myregistry.azurecr.io'
    assert [r['name'] for r in load_repos.call_args.args[1]] == REPOSITORY_NAMES
    assert load_images.call_count == 2
    assert load_status.call_args.args[2] == {
        'repositories_fetched': True, 'repositories_fetch_error': None, 'image_fetch_failures': 0,
    }
    client.close.assert_called_once()


@patch(f'{MODULE}.load_registry_fetch_status')
@patch(f'{MODULE}.load_repositories')
@patch(f'{MODULE}.get_registry_client')
def test_sync_registry_contents_skips_registry_without_data_plane_role(get_client, load_repos, load_status, caplog):
    for error, reason in [
        (_http_error(401, ClientAuthenticationError), 'http_401'),
        (_http_error(403), 'http_403'),
        (ServiceRequestError('name resolution failed'), 'unreachable'),
    ]:
        caplog.clear()
        load_status.reset_mock()
        client = MagicMock()
        client.list_repository_names.side_effect = error
        get_client.return_value = client

        with caplog.at_level(logging.WARNING, logger=MODULE):
            sync_registry_contents(Mock(), Mock(), REGISTRY, 7)

        load_repos.assert_not_called()
        assert load_status.call_args.args[2]['repositories_fetched'] is False
        assert load_status.call_args.args[2]['repositories_fetch_error'] == reason
        warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warnings) == 1
        assert 'Container Registry Repository Catalog Lister' in warnings[0].getMessage()
        client.close.assert_called_once()


@patch(f'{MODULE}.load_registry_fetch_status')
@patch(f'{MODULE}.get_registry_client')
def test_sync_registry_contents_does_not_call_private_registries(get_client, load_status):
    sync_registry_contents(Mock(), Mock(), {**REGISTRY, 'public_network_access': 'Disabled'}, 7)

    get_client.assert_not_called()
    assert load_status.call_args.args[2]['repositories_fetch_error'] == 'public_network_access_disabled'


@patch(f'{MODULE}.load_registry_fetch_status')
@patch(f'{MODULE}.load_images')
@patch(f'{MODULE}.load_repositories')
@patch(f'{MODULE}.get_registry_client')
def test_sync_registry_contents_keeps_going_when_one_repository_fails(
    get_client, load_repos, load_images, load_status, caplog,
):
    client = _client()

    def manifests(name, **kwargs):
        if name == 'webapp':
            raise _http_error(403)
        return iter(MANIFESTS)
    client.list_manifest_properties.side_effect = manifests
    get_client.return_value = client

    with caplog.at_level(logging.WARNING, logger=MODULE):
        sync_registry_contents(Mock(), Mock(), REGISTRY, 7)

    assert load_images.call_count == 1
    assert load_status.call_args.args[2]['repositories_fetched'] is True
    assert load_status.call_args.args[2]['image_fetch_failures'] == 1
    assert len([r for r in caplog.records if r.levelno == logging.WARNING]) == 1


@patch(f'{MODULE}.cleanup_container_images')
@patch(f'{MODULE}.cleanup_container_repositories')
@patch(f'{MODULE}.cleanup_container_registries')
@patch(f'{MODULE}.sync_registry_contents')
@patch(f'{MODULE}.load_registries')
@patch(f'{MODULE}.get_registry_list')
def test_sync(get_registries, load_registries, sync_contents, cleanup_registries, cleanup_repos, cleanup_images):
    get_registries.return_value = [REGISTRY]
    session, credentials, params = Mock(), Mock(), {}

    sync(session, credentials, 'sub-123', 7, params, ['eastus'])

    get_registries.assert_called_once_with(credentials, 'sub-123', ['eastus'], params)
    load_registries.assert_called_once_with(session, 'sub-123', [REGISTRY], 7)
    sync_contents.assert_called_once_with(session, credentials, REGISTRY, 7)
    cleanup_registries.assert_called_once_with(session, params)
    cleanup_repos.assert_called_once_with(session, params)
    cleanup_images.assert_called_once_with(session, params)


@patch(f'{MODULE}.run_cleanup_job')
@patch(f'{MODULE}.get_registry_list', return_value=[])
@patch(f'{MODULE}.load_registries')
def test_sync_cleans_children_before_parents(load_registries, get_registries, run_cleanup_job):
    sync(Mock(), Mock(), 'sub-123', 7, {})

    assert [c.args[0] for c in run_cleanup_job.call_args_list] == [
        'azure_container_images_cleanup.json',
        'azure_container_repositories_cleanup.json',
        'azure_container_registries_cleanup.json',
    ]
