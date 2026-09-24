from typing import Dict

from googleapiclient.errors import HttpError


def is_permission_error(e: HttpError, err: Dict) -> bool:
    """
    True when a GCP API call was refused for lack of permission. `err` is the parsed `error` body.

    Older APIs (Compute, Cloud SQL, BigQuery, DNS) return 403 with reason forbidden/notAuthorized and no
    status=PERMISSION_DENIED, so the HTTP code is checked too (CDX-CARTOGRAPHY-INVENTORY-25B).
    """
    return e.resp.status == 403 or err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden'
