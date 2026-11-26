from unittest.mock import MagicMock

import pytest
from googleapiclient.errors import HttpError

from cartography.intel.gcp import crm


def _http_error(status):
    return HttpError(resp=MagicMock(status=status), content=b'{"error": {"code": %d, "message": "m"}}' % status)


def _client_failing_with(status):
    client = MagicMock()
    error = _http_error(status)
    client.organizations.return_value.search.return_value.execute.side_effect = error
    client.folders.return_value.search.return_value.execute.side_effect = error
    client.projects.return_value.list.return_value.execute.side_effect = error
    return client


GETTERS = [crm.get_gcp_organizations, crm.get_gcp_folders, crm.get_gcp_projects]


@pytest.mark.parametrize('getter', GETTERS)
@pytest.mark.parametrize('status', [500, 503, 429])
def test_a_transient_error_raises_instead_of_reading_as_empty(getter, status):
    # An empty org list switches the sync to a generated org id; empty folders get every folder cleaned up.
    with pytest.raises(HttpError):
        getter(_client_failing_with(status))


@pytest.mark.parametrize('getter', GETTERS)
def test_no_access_still_reads_as_empty(getter):
    assert getter(_client_failing_with(403)) == []
