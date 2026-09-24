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
