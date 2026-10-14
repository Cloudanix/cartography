import json
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


def test_handler_failure_republishes_original_request_once():
    received = ReceivedMessage(_request_payload())
    subscriber = MagicMock()

    with patch("gke.bitbucket_process_request", return_value={"status": "failure"}) as handler:
        with patch("gke.PubSubLibrary") as pubsub_cls:
            pubsub_cls.return_value.publish.return_value = True
            ok = gke.task_processing_handler(subscriber, "subscriptions/bitbucket", received)

    assert ok is False
    subscriber.acknowledge.assert_called_once()
    assert pubsub_cls.return_value.publish.call_count == 1
    _project_id, body, topic = pubsub_cls.return_value.publish.call_args.args
    published = json.loads(body)
    assert topic == "bitbucket-cartography-events-request"
    assert published["metadata"]["retryReason"] == "handler_failure"
    assert published["_retry_count"] == 1
    assert "neo4j" not in published
    assert "injected-secret" not in body
    handler_payload = handler.call_args.args[1]
    assert handler_payload["neo4j"]["pwd"] == "injected-secret"
    assert gke.current_payload is None
