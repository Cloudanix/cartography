import json
import os
import signal
import sys
import types
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest


def _import_gke():
    """Import the worker. Stub main when cartography deps are not installed."""
    try:
        import gke
        return gke
    except ModuleNotFoundError:
        sys.modules.pop("gke", None)
        sys.modules.pop("main", None)
        main_mod = types.ModuleType("main")
        main_mod.bitbucket_process_request = MagicMock(return_value={"status": "success"})
        main_mod.github_process_request = MagicMock(return_value={"status": "success"})
        main_mod.gitlab_process_request = MagicMock(return_value={"status": "success"})
        sys.modules["main"] = main_mod
        import gke
        return gke


gke = _import_gke()


class ReceivedMessage:
    def __init__(self, payload):
        self.message = MagicMock()
        self.message.data = json.dumps(payload).encode("utf-8")
        self.ack_id = "ack-1"


def _request_payload():
    return {
        "templateType": gke.CDX_BITBUCKET_TEMPLATE_TYPE,
        "eventId": "c5771acd-a2ae-4b04-bef5-b71c75e51f18",
        "requestTopic": "bitbucket-cartography-events-request",
        "resultTopic": "inventory-views-requests",
        "workspace": {"account_id": "mobilewaretech"},
        "metadata": None,
    }


@pytest.fixture(autouse=True)
def _reset_worker_state(monkeypatch):
    gke.current_payload = None
    gke.sigterm_received = False
    monkeypatch.setenv("CDX_LOG_LEVEL", "INFO")
    monkeypatch.setenv("CDX_PROJECT_ID", "cloudanix-app")
    monkeypatch.setenv("CDX_MAX_RETRIES", "3")
    monkeypatch.setenv("CDX_APP_NEO4J_URI", "bolt://neo4j.test")
    monkeypatch.setenv("CDX_APP_NEO4J_USER", "neo4j")
    monkeypatch.setenv("CDX_APP_NEO4J_PWD", "injected-secret")
    monkeypatch.setenv("CDX_APP_ENV", "TEST")


def test_republish_sends_original_request_to_request_topic():
    logger = MagicMock()
    payload = _request_payload()

    with patch("gke.PubSubLibrary") as pubsub_cls:
        pubsub_cls.return_value.publish.return_value = True
        ok = gke.republish_message_to_pubsub(payload, payload["templateType"], logger, retry_reason="sigterm")

    assert ok is True
    project_id, body, topic = pubsub_cls.return_value.publish.call_args.args
    published = json.loads(body)
    assert project_id == "cloudanix-app"
    assert topic == "bitbucket-cartography-events-request"
    assert published["resultTopic"] == "inventory-views-requests"
    assert "response" not in published
    assert published["_retry_count"] == 1
    assert published["metadata"]["retryReason"] == "sigterm"
    assert published["metadata"]["isRetry"] is True
    assert published["metadata"]["retryCount"] == 1


def test_republish_drops_message_at_max_retries():
    logger = MagicMock()
    payload = _request_payload()
    payload["_retry_count"] = 3

    with patch("gke.PubSubLibrary") as pubsub_cls:
        ok = gke.republish_message_to_pubsub(payload, payload["templateType"], logger, retry_reason="sigterm")

    assert ok is False
    pubsub_cls.return_value.publish.assert_not_called()


def test_sigterm_republishes_inflight_request_and_exits():
    gke.current_payload = _request_payload()

    with patch("gke.PubSubLibrary") as pubsub_cls:
        pubsub_cls.return_value.publish.return_value = True
        with pytest.raises(SystemExit) as exc:
            gke.handle_sigterm(15, None)

    assert exc.value.code == 0
    assert gke.sigterm_received is True
    _project_id, body, topic = pubsub_cls.return_value.publish.call_args.args
    published = json.loads(body)
    assert topic == "bitbucket-cartography-events-request"
    assert published["metadata"]["retryReason"] == "sigterm"
    assert published["eventId"] == "c5771acd-a2ae-4b04-bef5-b71c75e51f18"
    assert "response" not in published


def test_sigterm_without_inflight_payload_does_not_publish():
    with patch("gke.PubSubLibrary") as pubsub_cls:
        with pytest.raises(SystemExit) as exc:
            gke.handle_sigterm(15, None)

    assert exc.value.code == 0
    pubsub_cls.return_value.publish.assert_not_called()


def test_sigterm_during_processing_republishes_once_and_skips_failure_republish():
    received = ReceivedMessage(_request_payload())
    subscriber = MagicMock()

    def _preempted(logger, payload):
        payload["neo4j"]["pwd"] = "injected-secret"
        gke.handle_sigterm(15, None)
        return {"status": "failure"}

    with patch("gke.bitbucket_process_request", side_effect=_preempted):
        with patch("gke.PubSubLibrary") as pubsub_cls:
            pubsub_cls.return_value.publish.return_value = True
            with pytest.raises(SystemExit) as exc:
                gke.task_processing_handler(subscriber, "subscriptions/bitbucket", received)

    assert exc.value.code == 0
    assert pubsub_cls.return_value.publish.call_count == 1
    _project_id, body, topic = pubsub_cls.return_value.publish.call_args.args
    published = json.loads(body)
    assert topic == "bitbucket-cartography-events-request"
    assert published["metadata"]["retryReason"] == "sigterm"
    assert published["_retry_count"] == 1
    assert "neo4j" not in published
    assert "injected-secret" not in body


def test_handler_failure_is_not_republished():
    received = ReceivedMessage(_request_payload())
    subscriber = MagicMock()

    with patch("gke.bitbucket_process_request", return_value={"status": "failure"}) as handler:
        with patch("gke.PubSubLibrary") as pubsub_cls:
            ok = gke.task_processing_handler(subscriber, "subscriptions/bitbucket", received)

    assert ok is False
    subscriber.acknowledge.assert_called_once()
    pubsub_cls.return_value.publish.assert_not_called()
    handler_payload = handler.call_args.args[1]
    assert handler_payload["neo4j"]["pwd"] == "injected-secret"
    assert gke.current_payload is None


def test_handler_exception_is_not_republished():
    subscriber = MagicMock()

    with patch("gke.bitbucket_process_request", side_effect=KeyError("message")):
        with patch("gke.PubSubLibrary") as pubsub_cls:
            ok = gke.task_processing_handler(subscriber, "subscriptions/bitbucket", ReceivedMessage(_request_payload()))

    assert ok is False
    pubsub_cls.return_value.publish.assert_not_called()
    assert gke.current_payload is None


def test_malformed_message_is_acked_and_dropped():
    received = ReceivedMessage({})
    received.message.data = b"{not-json"
    subscriber = MagicMock()

    with patch("gke.PubSubLibrary") as pubsub_cls:
        ok = gke.task_processing_handler(subscriber, "subscriptions/bitbucket", received)

    assert ok is False
    subscriber.acknowledge.assert_called_once()
    pubsub_cls.return_value.publish.assert_not_called()


def test_second_sigterm_does_not_republish_again():
    gke.current_payload = _request_payload()
    gke.sigterm_received = True

    with patch("gke.PubSubLibrary") as pubsub_cls:
        assert gke.handle_sigterm(15, None) is None

    pubsub_cls.return_value.publish.assert_not_called()
    assert "_retry_count" not in gke.current_payload


def test_retry_count_carries_across_jobs_and_stops_after_three_sigterms():
    """Each loop is one KEDA job: pull the last republished body, get preempted."""
    body = json.dumps(_request_payload())
    published_counts = []

    def _preempted(logger, payload):
        gke.handle_sigterm(15, None)

    for _job in range(4):
        gke.current_payload = None
        gke.sigterm_received = False
        received = ReceivedMessage({})
        received.message.data = body.encode("utf-8")

        with patch("gke.bitbucket_process_request", side_effect=_preempted):
            with patch("gke.PubSubLibrary") as pubsub_cls:
                pubsub_cls.return_value.publish.return_value = True
                with pytest.raises(SystemExit):
                    gke.task_processing_handler(MagicMock(), "subscriptions/bitbucket", received)

        if pubsub_cls.return_value.publish.called:
            body = pubsub_cls.return_value.publish.call_args.args[1]
            published_counts.append(json.loads(body)["_retry_count"])

    # Original run + 3 retries. The 4th preemption drops the request.
    assert published_counts == [1, 2, 3]
    final = json.loads(body)
    assert final["metadata"]["retryCount"] == 3
    assert final["metadata"]["retryReason"] == "sigterm"
    assert final["eventId"] == "c5771acd-a2ae-4b04-bef5-b71c75e51f18"
    assert "neo4j" not in final


def test_real_os_sigterm_during_handler_republishes_once():
    """Deliver an actual SIGTERM to this process mid-sync, as the kubelet does."""
    subscriber = MagicMock()
    previous = signal.signal(signal.SIGTERM, gke.handle_sigterm)

    def _sync_interrupted_by_kubelet(logger, payload):
        os.kill(os.getpid(), signal.SIGTERM)
        # The handler runs at the next bytecode and raises SystemExit first.
        raise AssertionError("SIGTERM handler did not interrupt the sync")

    try:
        with patch("gke.bitbucket_process_request", side_effect=_sync_interrupted_by_kubelet):
            with patch("gke.PubSubLibrary") as pubsub_cls:
                pubsub_cls.return_value.publish.return_value = True
                with pytest.raises(SystemExit) as exc:
                    gke.task_processing_handler(
                        subscriber,
                        "subscriptions/bitbucket",
                        ReceivedMessage(_request_payload()),
                    )
    finally:
        signal.signal(signal.SIGTERM, previous)

    assert exc.value.code == 0
    assert pubsub_cls.return_value.publish.call_count == 1
    published = json.loads(pubsub_cls.return_value.publish.call_args.args[1])
    assert published["metadata"]["retryReason"] == "sigterm"
    assert "neo4j" not in published
