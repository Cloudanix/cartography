from typing import Any

import googleapiclient.discovery
from googleapiclient.discovery import Resource
from googleapiclient.http import HttpRequest

# Google APIs answer a few calls a day with a short-lived 5xx ("The service is currently unavailable.") for one
# project or region. With num_retries, googleapiclient retries 5xx, 429 and rate-limit 403s with randomized
# exponential backoff (worst case ~31s over 5 retries) before raising; it never retries other 4xx.
GCP_API_NUM_RETRIES = 5


class RetryingHttpRequest(HttpRequest):
    """An HttpRequest whose execute() retries transient errors by default, so no call site can forget to."""

    def execute(self, http: Any = None, num_retries: int = GCP_API_NUM_RETRIES) -> Any:
        return super().execute(http=http, num_retries=num_retries)


def build_gcp_client(service: str, version: str, **kwargs: Any) -> Resource:
    """
    googleapiclient.discovery.build() for every GCP client cartography uses: each request the client creates
    (list_next pages included, they copy the request) is a RetryingHttpRequest.
    """
    return googleapiclient.discovery.build(service, version, requestBuilder=RetryingHttpRequest, **kwargs)
