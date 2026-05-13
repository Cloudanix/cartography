import os
from typing import Optional

import sentry_sdk
from sentry_sdk import capture_exception
from sentry_sdk import capture_message

sentry_sdk.init(
    dsn=os.environ.get("CDX_SENTRY_DSN"),
    # Set traces_sample_rate to 1.0 to capture 100%
    # of transactions for performance monitoring.
    # We recommend adjusting this value in production.
    traces_sample_rate=0.1,
)


def capture_error(
    message: str,
    error: BaseException,
    extra: Optional[dict],
):
    if os.getenv("CDX_APP_ENV") == "PRODUCTION":
        if extra:
            extra = extra or {}
            extra["message"] = message
            sentry_sdk.set_extra("context", extra)

        # If error is "Unable to retrieve routing information", skip it
        if str(error) == "Unable to retrieve routing information":
            return

        capture_exception(error)

    else:
        pass


def capture_warning(message: str, extra: dict | None = None):
    if os.getenv("CDX_APP_ENV") == "PRODUCTION":
        if extra:
            sentry_sdk.set_context("context", extra)

        capture_message(message)

    else:
        pass
