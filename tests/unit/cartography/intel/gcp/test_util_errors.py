import json
from unittest.mock import MagicMock

import pytest
from googleapiclient.errors import HttpError

from cartography.intel.gcp.util.errors import is_permission_error


def _error(status: int, body: dict) -> HttpError:
    return HttpError(resp=MagicMock(status=status), content=json.dumps({'error': body}).encode())


@pytest.mark.parametrize(
    'status, body, expected',
    [
        # Compute v1 (CDX-CARTOGRAPHY-INVENTORY-25B)
        (403, {'code': 403, 'message': "Required 'compute.regions.list' permission", 'errors': [{'reason': 'forbidden'}]}, True),
        # Cloud SQL Admin (CDX-CARTOGRAPHY-INVENTORY-88A)
        (403, {'code': 403, 'message': 'The client is not authorized to make this request.', 'errors': [{'reason': 'notAuthorized'}]}, True),
        (403, {'code': 403, 'status': 'PERMISSION_DENIED', 'message': 'denied'}, True),
        (404, {'code': 404, 'message': 'Not found', 'errors': [{'reason': 'notFound'}]}, False),
        (503, {'code': 503, 'message': 'The service is currently unavailable.'}, False),
    ],
)
def test_is_permission_error(status, body, expected):
    e = _error(status, body)
    assert is_permission_error(e, body) is expected
