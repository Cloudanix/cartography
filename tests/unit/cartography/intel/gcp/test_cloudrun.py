from unittest.mock import MagicMock

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
