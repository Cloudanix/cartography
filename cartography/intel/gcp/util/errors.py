import json
from typing import Dict

from googleapiclient.errors import HttpError


TRANSIENT_403_REASONS = {
    "rateLimitExceeded",
    "userRateLimitExceeded",
    "dailyLimitExceeded",
    "quotaExceeded",
}


def is_permission_error(e: HttpError, err: Dict) -> bool:
    """
    True when a GCP API call was refused for lack of permission. `err` is the parsed `error` body.

    Older APIs (Compute, Cloud SQL, BigQuery, DNS) return 403 with reason forbidden/notAuthorized and no
    status=PERMISSION_DENIED, so the HTTP code is checked too (CDX-CARTOGRAPHY-INVENTORY-25B).
    Transient quota and rate-limit 403s are not permission denials and must be treated as retriable.
    """
    if err.get("status", "") == "PERMISSION_DENIED":
        return True

    reasons = {
        item.get("reason")
        for item in err.get("errors", [])
        if isinstance(item, dict) and item.get("reason")
    }
    if reasons & TRANSIENT_403_REASONS:
        return False

    if e.resp.status != 403:
        return False

    if err.get("message", "") == "Forbidden":
        return True

    message = str(err.get("message", "")).lower()
    return bool(reasons & {"forbidden", "notAuthorized"}) or "forbidden" in message


def is_service_not_enabled_error(http_error: HttpError) -> bool:
    """
    Return True when the HttpError is GCP reporting that the API is not enabled / has never been used on the project.

    GCP signals this inconsistently across services, so all known shapes are matched centrally:
      - 403 with reason `accessNotConfigured` in the legacy `errors[]` array (e.g. Compute).
      - 403 PERMISSION_DENIED with reason `SERVICE_DISABLED` in the newer `details[]` (ErrorInfo) array.
      - 400 reason `invalid` with a "...has not enabled <API>" message (e.g. BigQuery).
      - any message saying the API "has not been used in project ... or it is disabled".

    Any other error returns False so it is re-raised / logged as an error and not silently swallowed.
    """
    try:
        error = json.loads(http_error.content.decode("utf-8")).get("error", {})
    except (AttributeError, UnicodeDecodeError, ValueError, TypeError):
        return False

    # Reason codes live in `errors[]` (legacy) and/or `details[]` (ErrorInfo) depending on the API.
    reason_entries = (error.get("errors") or []) + (error.get("details") or [])
    reasons = {entry.get("reason") for entry in reason_entries if isinstance(entry, dict)}
    if reasons & {"accessNotConfigured", "SERVICE_DISABLED"}:
        return True

    # Fall back to message text for APIs that don't set a recognizable reason code.
    message = error.get("message", "")
    if not message:
        return False
    return any(
        needle in message
        for needle in (
            "has not been used in project",
            "is disabled",
            "has not enabled",
            "has not been enabled",
        )
    )
