from unittest.mock import MagicMock

from googleapiclient.discovery import HttpError

from cartography.intel.gcp import cloudrun


def _service(name, region='us-central1', annotations=None, url=None):
    return {
        'metadata': {
            'name': name,
            'namespace': '123456',
            'labels': {'cloud.googleapis.com/location': region},
            'annotations': annotations or {},
        },
        'status': {'url': url or f'https://{name}-abc-uc.a.run.app'},
    }


def _list_client(pages):
    client = MagicMock()
    client.namespaces.return_value.services.return_value.list.return_value.execute.side_effect = pages
    return client


def test_get_cloudrun_services_follows_continue_token():
    client = _list_client([
        {'items': [_service('a')], 'metadata': {'continue': 'tok'}},
        {'items': [_service('b')], 'metadata': {}},
    ])

    services = cloudrun.get_cloudrun_services(client, 'p1', {})

    assert [s['metadata']['name'] for s in services] == ['a', 'b']
    list_calls = client.namespaces.return_value.services.return_value.list.call_args_list
    assert list_calls[0].kwargs == {'parent': 'namespaces/p1'}
    assert list_calls[1].kwargs == {'parent': 'namespaces/p1', 'continue': 'tok'}


def test_transform_services_keeps_every_service(mocker):
    mocker.patch.object(cloudrun.gcp_console_link, 'get_console_link', return_value='link')
    services = [
        _service('public', annotations={'run.googleapis.com/ingress': 'all'}),
        _service(
            'lb-only', region='europe-west1', annotations={
                'run.googleapis.com/ingress': 'internal-and-cloud-load-balancing',
                'run.googleapis.com/invoker-iam-disabled': 'true',
            },
        ),
        {'metadata': {'name': 'bare'}, 'status': {}},
    ]

    result = {s['metadata']['name']: s for s in cloudrun.transform_services(services, 'p1')}

    assert set(result) == {'public', 'lb-only', 'bare'}
    assert result['public']['id'] == 'projects/p1/services/public'
    assert result['public']['region'] == 'us-central1'
    assert result['public']['ingress'] == 'all'
    assert result['public']['invoker_iam_disabled'] is False
    assert result['public']['url'] == 'https://public-abc-uc.a.run.app'
    assert result['lb-only']['region'] == 'europe-west1'
    assert result['lb-only']['ingress'] == 'internal-and-cloud-load-balancing'
    assert result['lb-only']['invoker_iam_disabled'] is True
    # No labels or annotations (never seen from the API, but must not abort the sync).
    assert result['bare']['region'] is None
    assert result['bare']['ingress'] is None


def _http_error(status):
    content = f'{{"error": {{"code": {status}, "message": "m", "status": "S"}}}}'.encode()
    return HttpError(resp=MagicMock(status=status), content=content)


def _transformed(name, ingress='all', invoker_iam_disabled=False, region='us-central1'):
    return {
        'metadata': {'name': name}, 'region': region, 'ingress': ingress,
        'invoker_iam_disabled': invoker_iam_disabled,
    }


def _iam_client(policies):
    """Cloud Run v2 client: getIamPolicy returns (or raises) policies[service name] in call order."""
    client = MagicMock()
    services = client.projects.return_value.locations.return_value.services.return_value

    def get_iam_policy(resource):
        outcome = policies[resource.split('/')[-1]]
        request = MagicMock()
        if isinstance(outcome, Exception):
            request.execute.side_effect = outcome
        else:
            request.execute.return_value = outcome
        return request
    services.getIamPolicy.side_effect = get_iam_policy
    return client


def _called_services(client):
    services = client.projects.return_value.locations.return_value.services.return_value
    return [c.kwargs['resource'] for c in services.getIamPolicy.call_args_list]


def test_resolve_invokers_records_public_members_of_invoking_roles():
    services = [
        _transformed('anyone'), _transformed('google-accounts'), _transformed('viewer-only'),
        _transformed('custom-role'), _transformed('private', ingress=None),
    ]
    client = _iam_client({
        'anyone': {'bindings': [{'role': 'roles/run.invoker', 'members': ['allUsers', 'user:a@x.com']}]},
        'google-accounts': {'bindings': [{'role': 'roles/run.servicesInvoker', 'members': ['allAuthenticatedUsers']}]},
        # roles/run.viewer cannot invoke: allUsers can read the service, not call it.
        'viewer-only': {'bindings': [{'role': 'roles/run.viewer', 'members': ['allUsers']}]},
        # A custom role's permissions are not resolved: treated as able to invoke (fail-safe).
        'custom-role': {'bindings': [{'role': 'projects/p1/roles/caller', 'members': ['allUsers']}]},
        'private': {},
    })

    cloudrun.resolve_service_invokers(client, services, 'p1')

    by_name = {s['metadata']['name']: s for s in services}
    assert by_name['anyone']['public_invokers'] == ['allUsers']
    assert by_name['google-accounts']['public_invokers'] == ['allAuthenticatedUsers']
    assert by_name['viewer-only']['public_invokers'] == []
    assert by_name['custom-role']['public_invokers'] == ['allUsers']
    assert by_name['private']['public_invokers'] == []
    assert {s['iam_policy_status'] for s in services} == {'resolved'}
    assert _called_services(client)[0] == 'projects/p1/locations/us-central1/services/anyone'


def test_resolve_invokers_skips_services_whose_policy_cannot_matter():
    services = [
        _transformed('internal', ingress='internal'),
        _transformed('no-iam-check', invoker_iam_disabled=True),
        _transformed('lb', ingress='internal-and-cloud-load-balancing'),
    ]
    client = _iam_client({'lb': {}})

    cloudrun.resolve_service_invokers(client, services, 'p1')

    assert _called_services(client) == ['projects/p1/locations/us-central1/services/lb']
    assert [s['iam_policy_status'] for s in services] == ['not_needed', 'not_needed', 'resolved']


def test_resolve_invokers_marks_failures_unresolved():
    services = [_transformed('flaky'), _transformed('ok'), _transformed('denied'), _transformed('after-denied')]
    client = _iam_client({
        'flaky': _http_error(500),
        'ok': {'bindings': [{'role': 'roles/run.invoker', 'members': ['allUsers']}]},
        'denied': _http_error(403),
        'after-denied': {},
    })

    cloudrun.resolve_service_invokers(client, services, 'p1')

    # A 403 means the role lacks run.services.getIamPolicy: the rest of the project would fail the same way.
    assert [r.split('/')[-1] for r in _called_services(client)] == ['flaky', 'ok', 'denied']
    assert [s['iam_policy_status'] for s in services] == ['unresolved', 'resolved', 'unresolved', 'unresolved']
    assert services[0]['public_invokers'] == []
