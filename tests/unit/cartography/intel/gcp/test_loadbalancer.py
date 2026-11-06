from unittest.mock import MagicMock

import pytest
from googleapiclient.discovery import HttpError

from cartography.intel.gcp.loadbalancer import get_compute_zones

# Compute v1 permission errors carry neither status=PERMISSION_DENIED nor message="Forbidden".
COMPUTE_PERMISSION_CONTENT = (
    b'{"error": {"code": 403, "message": "Required \'compute.zones.list\' permission for \'projects/p\'", '
    b'"errors": [{"reason": "forbidden"}]}}'
)
NOT_FOUND_CONTENT = b'{"error": {"code": 404, "message": "Not found", "errors": [{"reason": "notFound"}]}}'


def _compute_raising(status: int, content: bytes) -> MagicMock:
    compute = MagicMock()
    compute.zones().list.return_value.execute.side_effect = HttpError(resp=MagicMock(status=status), content=content)
    return compute


# Same shape as https://cloudanix.sentry.io/issues/CDX-CARTOGRAPHY-INVENTORY-25B (compute.regions.list).
def test_get_compute_zones_handles_compute_permission_error():
    assert get_compute_zones(_compute_raising(403, COMPUTE_PERMISSION_CONTENT), "p") == []


def test_get_compute_zones_reraises_other_http_errors():
    with pytest.raises(HttpError):
        get_compute_zones(_compute_raising(404, NOT_FOUND_CONTENT), "p")
