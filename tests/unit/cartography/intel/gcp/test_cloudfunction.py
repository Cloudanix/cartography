import json
from unittest.mock import MagicMock

from googleapiclient.http import HttpMockSequence
from googleapiclient.http import HttpRequest
from googleapiclient.model import JsonModel

from cartography.intel.gcp.cloudfunction import get_gcp_functions

UNAVAILABLE_503 = json.dumps({'error': {'code': 503, 'message': 'The service is currently unavailable.'}})


def _real_request(responses):
    # A real HttpRequest over canned responses, so googleapiclient's own retry loop runs.
    return HttpRequest(
        HttpMockSequence(responses), JsonModel().response, 'https://cloudfunctions.googleapis.com/v1/x',
    )


def _function_client(functions):
    client = MagicMock()
    locations = client.projects.return_value.locations.return_value
    locations.list.return_value.execute.return_value = {
        'locations': [{'name': 'projects/p1/locations/us-central1', 'locationId': 'us-central1'}],
    }
    locations.list_next.return_value = None
    locations.functions.return_value.list.return_value.execute.return_value = {'functions': functions}
    locations.functions.return_value.list_next.return_value = None
    return client


def test_get_gcp_functions_records_trigger_kind(mocker):
    mocker.patch('cartography.intel.gcp.cloudfunction.gcp_console_link.get_console_link', return_value='link')
    client = _function_client([
        {'name': 'projects/p1/locations/us-central1/functions/http', 'httpsTrigger': {'url': 'https://fn.example'}},
        {
            'name': 'projects/p1/locations/us-central1/functions/event',
            'eventTrigger': {'eventType': 'google.pubsub.topic.publish', 'resource': 'projects/p1/topics/t'},
        },
    ])

    functions = {f['function_name']: f for f in get_gcp_functions(client, 'p1', [], {})}

    assert functions['http']['https_trigger_url'] == 'https://fn.example'
    assert functions['http']['event_trigger_type'] is None
    assert functions['event']['https_trigger_url'] is None
    assert functions['event']['event_trigger_type'] == 'google.pubsub.topic.publish'


def test_get_gcp_functions_retries_a_transient_503(mocker):
    mocker.patch('cartography.intel.gcp.cloudfunction.gcp_console_link.get_console_link', return_value='link')
    mocker.patch('googleapiclient.http.time.sleep')
    client = _function_client([])
    client.projects.return_value.locations.return_value.functions.return_value.list.return_value = _real_request([
        ({'status': '503'}, UNAVAILABLE_503),
        ({'status': '200'}, json.dumps({'functions': [{'name': 'projects/p1/locations/us-central1/functions/f'}]})),
    ])

    functions = get_gcp_functions(client, 'p1', [], {})

    assert [f['function_name'] for f in functions] == ['f']
