import json
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from googleapiclient.errors import HttpError

import cartography.intel.gcp
from cartography.intel.gcp import _GATEABLE_SERVICE_APIS
from cartography.intel.gcp import _initialize_resources
from cartography.intel.gcp import containerregistry
from cartography.intel.gcp import Resources
from cartography.intel.gcp.resources import RESOURCE_FUNCTIONS

PROJECT_ID = 'test-project'
UPDATE_TAG = 123


def _common_job_parameters():
    return {
        'UPDATE_TAG': UPDATE_TAG,
        'GCP_PROJECT_ID': PROJECT_ID,
        'GCP_ORGANIZATION_ID': 'org-1',
        'WORKSPACE_ID': 'ws-1',
        'service_labels': [],
    }


def test_artifacts_has_a_resources_field():
    # The dispatcher calls RESOURCE_FUNCTIONS[name](session, getattr(resources, name), ...). Without the field the
    # getattr raised AttributeError and the artifacts sync never ran.
    assert 'artifacts' in RESOURCE_FUNCTIONS
    assert 'artifacts' in Resources._fields


@patch.object(cartography.intel.gcp, '_get_admin_resource')
@patch('googleapiclient.discovery.build')
def test_artifacts_client_is_artifact_registry_v1(mock_build, mock_admin):
    resources = _initialize_resources(MagicMock(), MagicMock())

    calls = [c for c in mock_build.call_args_list if c.args[0] == 'artifactregistry']
    assert len(calls) == 1
    assert calls[0].args[1] == 'v1'
    assert resources.artifacts is mock_build.return_value


def test_artifacts_is_gated_on_the_artifact_registry_api():
    # Projects without artifactregistry.googleapis.com enabled are skipped before any call.
    assert _GATEABLE_SERVICE_APIS['artifacts'] == 'artifactregistry.googleapis.com'


@patch.object(containerregistry, 'run_cleanup_job')
def test_sync_uses_the_client_it_is_given(mock_cleanup):
    client = MagicMock()
    client.projects().locations().list().execute.return_value = {'locations': []}
    client.projects().locations().list_next.return_value = None

    # No client of its own: the old sync treated the Resource as credentials and built two clients, the second
    # being "containerregistry v1alpha1", which has no discovery document.
    with patch('googleapiclient.discovery.build', side_effect=AssertionError('sync must not build a client')):
        containerregistry.sync(MagicMock(), client, PROJECT_ID, UPDATE_TAG, _common_job_parameters(), ['us-central1'])

    client.projects().locations().list.assert_called_with(name=f'projects/{PROJECT_ID}')


def _http_error(status, error):
    return HttpError(resp=MagicMock(status=status), content=json.dumps({'error': error}).encode())


PERMISSION_DENIED = {
    'code': 403, 'status': 'PERMISSION_DENIED',
    'message': "Permission 'artifactregistry.locations.list' denied on resource",
}
SERVICE_DISABLED = {
    'code': 403, 'status': 'PERMISSION_DENIED',
    'message': 'Artifact Registry API has not been used in project 123 before or it is disabled.',
    'details': [{'@type': 'type.googleapis.com/google.rpc.ErrorInfo', 'reason': 'SERVICE_DISABLED'}],
}


def test_permission_denied_is_one_warning_and_an_empty_result(caplog):
    client = MagicMock()
    client.projects().locations().list().execute.side_effect = _http_error(403, PERMISSION_DENIED)

    assert containerregistry.get_artifact_registry_locations(client, PROJECT_ID) == []
    assert [r.levelname for r in caplog.records if 'permissions' in r.getMessage()] == ['WARNING']


def test_disabled_api_raises_for_the_dispatcher_to_skip_quietly():
    # SERVICE_DISABLED also carries status PERMISSION_DENIED; it must not be swallowed as a permission warning.
    client = MagicMock()
    client.projects().locations().list().execute.side_effect = _http_error(403, SERVICE_DISABLED)

    with pytest.raises(HttpError) as raised:
        containerregistry.get_artifact_registry_locations(client, PROJECT_ID)
    assert cartography.intel.gcp._is_service_not_enabled_error(raised.value) is True
