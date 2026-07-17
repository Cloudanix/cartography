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

# Newer serviceusage shape: reason SERVICE_DISABLED lives in details[] (ErrorInfo), not errors[].
SERVICE_DISABLED_DETAILS_CONTENT = (
    b'{"error": {"code": 403, "status": "PERMISSION_DENIED", "message": "Cloud Functions API '
    b'has not been used in project 123 before or it is disabled.", "details": [{"@type": '
    b'"type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED"}]}}'
)

# Some APIs phrase it "has not been enabled" (the extra "been" must still match).
HAS_NOT_BEEN_ENABLED_CONTENT = (
    b'{"error": {"code": 403, "message": "Cloud Spanner API has not been enabled on project 123.", '
    b'"errors": [{"reason": "failedPrecondition"}]}}'
)

# Errors that must NOT be treated as service-not-enabled (real failures that should still surface).
REAL_PERMISSION_CONTENT = (
    b'{"error": {"code": 403, "message": "The caller does not have permission", '
    b'"errors": [{"reason": "forbidden"}]}}'
)
NOT_FOUND_CONTENT = b'{"error": {"code": 404, "message": "Not found", "errors": [{"reason": "notFound"}]}}'


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


@pytest.mark.parametrize(
    "content, status",
    [
        (SERVICE_DISABLED_CONTENT, 403),
        (BIGQUERY_NOT_ENABLED_CONTENT, 400),
        (SERVICE_DISABLED_DETAILS_CONTENT, 403),
        (HAS_NOT_BEEN_ENABLED_CONTENT, 403),
    ],
)
def test_is_service_not_enabled_matches_all_disabled_shapes(content, status):
    # Every known GCP "API not enabled" shape must be recognized so both the parallel (concurrent_execution)
    # and serial paths downgrade it to info instead of an error (Sentry).
    err = HttpError(resp=MagicMock(status=status), content=content)
    assert _is_service_not_enabled_error(err) is True


@pytest.mark.parametrize(
    "content, status",
    [
        (REAL_PERMISSION_CONTENT, 403),
        (NOT_FOUND_CONTENT, 404),
        (b"not json at all", 500),
    ],
)
def test_is_service_not_enabled_rejects_real_errors(content, status):
    # Genuine failures must NOT be classified as service-not-enabled, or they'd be silently swallowed.
    err = HttpError(resp=MagicMock(status=status), content=content)
    assert _is_service_not_enabled_error(err) is False
