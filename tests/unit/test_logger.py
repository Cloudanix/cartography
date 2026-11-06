from unittest.mock import patch

import pytest

from utils.logger import Logger


@pytest.fixture
def prod(monkeypatch):
    monkeypatch.setenv("CDX_APP_ENV", "PRODUCTION")


@patch("utils.logger.capture_error")
@patch("utils.logger.capture_warning")
def test_warning_outside_except_sends_labeled_message(capture_warning, capture_error, prod):
    # https://cloudanix.sentry.io/issues/6763414736/
    # sys.exc_info() is (None, None, None) here, a truthy tuple; it used to go to capture_exception
    # and show up in Sentry as a level=error "<unlabeled event>" with the message lost.
    Logger("INFO").warning("Maximum runtime has been reached", extra={"handle": "h"})

    capture_error.assert_not_called()
    capture_warning.assert_called_once_with("Maximum runtime has been reached", extra={"handle": "h"}, level="warning")


@patch("utils.logger.capture_error")
@patch("utils.logger.capture_warning")
def test_error_outside_except_keeps_error_level(capture_warning, capture_error, prod):
    Logger("INFO").error("boom")

    capture_error.assert_not_called()
    capture_warning.assert_called_once_with("boom", extra=None, level="error")


@patch("utils.logger.capture_error")
@patch("utils.logger.capture_warning")
def test_error_inside_except_captures_exception(capture_warning, capture_error, prod):
    try:
        raise ValueError("bad")
    except ValueError:
        Logger("INFO").error("failed")

    capture_warning.assert_not_called()
    assert capture_error.call_args.args[1][0] is ValueError
