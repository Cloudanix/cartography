from unittest.mock import MagicMock

import pytest
from googleapiclient.discovery import HttpError

from cartography.intel.gcp import _is_service_not_enabled_error
from cartography.intel.gcp import get_all_regions

SERVICE_DISABLED_CONTENT = (
    b'{"error": {"code": 403, "message": "Compute Engine API has not been used in '
    b'project canvas before or it is disabled.", "errors": [{"reason": "accessNotConfigured"}]}}'
)

# BigQuery reports a disabled service as 400 reason=invalid + "has not enabled BigQuery" (CDX example).
BIGQUERY_NOT_ENABLED_CONTENT = (
    b'{"error": {"code": 400, "message": "The project canvas has not enabled BigQuery.", '
    b'"errors": [{"message": "The project canvas has not enabled BigQuery.", "reason": "invalid"}]}}'
)


def test_get_all_regions_returns_region_names():
    compute = MagicMock()
    req = MagicMock()
    req.execute.return_value = {"items": [{"name": "us-east1"}, {"name": "us-west1"}]}
    compute.regions().list.return_value = req
    compute.regions().list_next.return_value = None

    assert get_all_regions(compute, "test-project") == ["us-east1", "us-west1"]


def test_get_all_regions_handles_disabled_compute_api():
    # Compute Engine API disabled -> 403; must not raise (would log as Sentry error), returns [].
    compute = MagicMock()
    req = MagicMock()
    req.execute.side_effect = HttpError(
        resp=MagicMock(status=403), content=SERVICE_DISABLED_CONTENT,
    )
    compute.regions().list.return_value = req

    assert get_all_regions(compute, "canvas") == []


def test_get_all_regions_reraises_other_http_errors():
    # A non-"service disabled" error (e.g. real permission denial) must still surface, not be swallowed.
    compute = MagicMock()
    req = MagicMock()
    req.execute.side_effect = HttpError(
        resp=MagicMock(status=403),
        content=b'{"error": {"code": 403, "message": "The caller does not have permission", '
        b'"errors": [{"reason": "forbidden"}]}}',
    )
    compute.regions().list.return_value = req

    with pytest.raises(HttpError):
        get_all_regions(compute, "no-perms")


def test_is_service_not_enabled_matches_bigquery_400():
    # Regression: BigQuery's 400 reason=invalid "has not enabled" must be treated as service-not-enabled so
    # concurrent_execution downgrades it to info instead of an error (Sentry).
    err = HttpError(resp=MagicMock(status=400), content=BIGQUERY_NOT_ENABLED_CONTENT)
    assert _is_service_not_enabled_error(err) is True
