from unittest.mock import MagicMock

import pytest
from googleapiclient.errors import HttpError

from cartography.intel.gcp import apigateway
from cartography.intel.gcp import dns
from cartography.intel.gcp import firestore
from cartography.intel.gcp.util.errors import is_transient_error


def _http_error(status):
    body = b'{"error": {"code": %d, "status": "%s", "message": "m"}}' % (
        status, b'PERMISSION_DENIED' if status == 403 else b'UNAVAILABLE',
    )
    return HttpError(resp=MagicMock(status=status), content=body)


def _dns_rrs(status):
    client = MagicMock()
    client.resourceRecordSets.return_value.list.return_value.execute.side_effect = _http_error(status)
    return dns.get_dns_rrs(client, {'id': 'z', 'name': 'z'}, 'p1')


def _dns_keys(status):
    client = MagicMock()
    client.dnsKeys.return_value.list.return_value.execute.side_effect = _http_error(status)
    return dns.get_dns_keys(client, {'id': 'z', 'name': 'z'}, 'p1')


def _firestore_indexes(status):
    client = MagicMock()
    indexes = client.projects.return_value.databases.return_value.collectionGroups.return_value.indexes.return_value
    indexes.list.return_value.execute.side_effect = _http_error(status)
    return firestore.get_firestore_indexes(client, {'name': 'projects/p1/databases/(default)'}, 'p1')


def _api_configs(status):
    client = MagicMock()
    configs = client.projects.return_value.locations.return_value.apis.return_value.configs.return_value
    configs.list.return_value.execute.side_effect = _http_error(status)
    return apigateway.get_api_configs(client, 'p1', {'name': 'projects/p1/locations/global/apis/a'}, [])


GETTERS = [_dns_rrs, _dns_keys, _firestore_indexes, _api_configs]


@pytest.mark.parametrize('getter', GETTERS)
def test_a_transient_error_raises_so_the_cleanup_is_skipped(getter):
    with pytest.raises(HttpError):
        getter(503)


@pytest.mark.parametrize('getter', GETTERS)
def test_no_access_still_reads_as_empty(getter):
    assert getter(403) == []


@pytest.mark.parametrize('status, transient', [(500, True), (503, True), (429, True), (403, False), (404, False)])
def test_is_transient_error(status, transient):
    assert is_transient_error(_http_error(status)) is transient
