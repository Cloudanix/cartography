from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from neo4j.exceptions import ClientError
from neo4j.exceptions import ServiceUnavailable
from neo4j.exceptions import TransientError

from cartography.graph.session import Session


def make_session():
    driver = MagicMock()
    session = Session(driver)
    return session, session.neo4j_session


class TestRun:
    def test_success_returns_driver_result(self):
        session, inner = make_session()
        result = session.run("MATCH (n) RETURN n", {"a": 1})
        assert result is inner.run.return_value
        inner.run.assert_called_once_with("MATCH (n) RETURN n", {"a": 1})

    @patch("cartography.graph.session.time.sleep")
    def test_transient_error_retries_then_succeeds(self, mock_sleep):
        session, inner = make_session()
        good = MagicMock()
        inner.run.side_effect = [TransientError("deadlock"), TransientError("deadlock"), good]

        result = session.run("q")

        assert result is good
        assert inner.run.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("cartography.graph.session.time.sleep")
    def test_transient_error_exhaustion_raises(self, mock_sleep):
        session, inner = make_session()
        inner.run.side_effect = TransientError("deadlock")

        with pytest.raises(TransientError):
            session.run("q", max_retries=3)

        # initial attempt + 3 retries
        assert inner.run.call_count == 4

    def test_client_error_raises_without_retry(self):
        session, inner = make_session()
        inner.run.side_effect = ClientError("bad syntax")

        with pytest.raises(ClientError):
            session.run("q")

        assert inner.run.call_count == 1

    def test_service_unavailable_raises(self):
        session, inner = make_session()
        inner.run.side_effect = ServiceUnavailable("down")

        with pytest.raises(ServiceUnavailable):
            session.run("q")

    def test_unexpected_exception_raises(self):
        session, inner = make_session()
        inner.run.side_effect = ValueError("boom")

        with pytest.raises(ValueError):
            session.run("q")


class TestExecuteWrite:
    def test_success_returns_tx_result(self):
        session, inner = make_session()
        tx_fn = MagicMock()

        result = session.execute_write(tx_fn, "arg", kw=1)

        assert result is inner.execute_write.return_value
        inner.execute_write.assert_called_once_with(tx_fn, "arg", kw=1)

    def test_failure_raises(self):
        session, inner = make_session()
        inner.execute_write.side_effect = ServiceUnavailable("down")

        with pytest.raises(ServiceUnavailable):
            session.execute_write(MagicMock())

    def test_unexpected_exception_raises(self):
        session, inner = make_session()
        inner.execute_write.side_effect = ValueError("boom")

        with pytest.raises(ValueError):
            session.execute_write(MagicMock())


class TestExecuteRead:
    def test_success_returns_tx_result(self):
        session, inner = make_session()
        tx_fn = MagicMock()

        result = session.execute_read(tx_fn)

        assert result is inner.execute_read.return_value

    def test_failure_raises(self):
        session, inner = make_session()
        inner.execute_read.side_effect = ClientError("denied")

        with pytest.raises(ClientError):
            session.execute_read(MagicMock())
