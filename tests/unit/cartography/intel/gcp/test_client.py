import json

import pytest
from googleapiclient.errors import HttpError
from googleapiclient.http import HttpMockSequence

from cartography.intel.gcp.util.client import build_gcp_client
from cartography.intel.gcp.util.client import GCP_API_NUM_RETRIES

UNAVAILABLE = ({'status': '503'}, json.dumps({'error': {'code': 503, 'message': 'unavailable'}}))
FORBIDDEN = ({'status': '403'}, json.dumps({'error': {'code': 403, 'status': 'PERMISSION_DENIED', 'message': 'no'}}))


def _compute(responses):
    # Built from the discovery doc bundled with googleapiclient, like prod, so no network call is made.
    http = HttpMockSequence(responses)
    return build_gcp_client('compute', 'v1', http=http, static_discovery=True), http


def test_every_request_of_a_built_client_retries_a_transient_503(mocker):
    mocker.patch('googleapiclient.http.time.sleep')
    compute, _ = _compute([UNAVAILABLE, ({'status': '200'}, json.dumps({'items': [{'name': 'us-east1-b'}]}))])

    zones = compute.zones().list(project='p1').execute()

    assert zones['items'] == [{'name': 'us-east1-b'}]


def test_list_next_pages_keep_retrying(mocker):
    # list_next copies the previous request, so later pages must still be RetryingHttpRequest.
    mocker.patch('googleapiclient.http.time.sleep')
    compute, _ = _compute([
        ({'status': '200'}, json.dumps({'items': [{'name': 'a'}], 'nextPageToken': 't'})),
        UNAVAILABLE,
        ({'status': '200'}, json.dumps({'items': [{'name': 'b'}]})),
    ])
    first = compute.zones().list(project='p1')
    page = first.execute()

    second = compute.zones().list_next(previous_request=first, previous_response=page)

    assert second.execute()['items'] == [{'name': 'b'}]


def test_a_permission_error_is_not_retried():
    compute, http = _compute([FORBIDDEN, UNAVAILABLE])

    with pytest.raises(HttpError):
        compute.zones().list(project='p1').execute()
    assert http._iterable == [UNAVAILABLE]  # only the 403 was used


def test_a_503_that_outlives_the_retries_raises(mocker):
    mocker.patch('googleapiclient.http.time.sleep')
    compute, http = _compute([UNAVAILABLE] * (GCP_API_NUM_RETRIES + 1))

    with pytest.raises(HttpError):
        compute.zones().list(project='p1').execute()
    assert http._iterable == []
