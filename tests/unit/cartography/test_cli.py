from types import SimpleNamespace

import pytest

from cartography import cli
from cartography import util


def _config():
    return SimpleNamespace(verbose=False, quiet=True)


def test_sync_response_without_failed_analysis_jobs():
    response = cli._sync_response({"UPDATE_TAG": 1791289020, "pagination": None})

    assert response["status"] == "success"
    assert response["failed_analysis_jobs"] == []


def test_sync_response_lists_failed_analysis_jobs():
    failed = [{"job": "bad_job.json", "scope": {"AWS_ID": "123456789012"}}]

    response = cli._sync_response({"UPDATE_TAG": 1791289020}, failed)

    # A failed analysis job does not fail the sync; it is reported next to the success.
    assert response["status"] == "success"
    assert response["updateTag"] == 1791289020
    assert response["failed_analysis_jobs"] == failed


def test_auth_failed_response_has_no_failed_analysis_jobs():
    response = cli._sync_response({"authFailed": True, "message": "no token"}, [{"job": "x.json", "scope": {}}])

    assert response["status"] == "failure"
    assert "failed_analysis_jobs" not in response


def test_process_reports_analysis_jobs_that_failed_during_the_sync(mocker):
    mocker.patch("cartography.util.GraphJob.run_from_json", side_effect=[RuntimeError("boom"), None])
    mocker.patch("cartography.util.read_text")

    def fake_sync(_sync, _config):
        params = {"WORKSPACE_ID": "ws-1", "AWS_ID": "123456789012"}
        util.run_analysis_job_logged("bad_job.json", mocker.Mock(), params)
        util.run_analysis_job_logged("good_job.json", mocker.Mock(), params)
        return {"UPDATE_TAG": 1791289020, "pagination": None}

    mocker.patch("cartography.sync.run_with_config", side_effect=fake_sync)

    response = cli.CLI(mocker.Mock(), prog="cartography").process(_config())

    assert response["status"] == "success"
    assert response["failed_analysis_jobs"] == [
        {"job": "bad_job.json", "scope": {"WORKSPACE_ID": "ws-1", "AWS_ID": "123456789012"}},
    ]


def test_sync_response_lists_withheld_services():
    assert cli._sync_response({"UPDATE_TAG": 1})["withheld_services"] == []

    response = cli._sync_response({"UPDATE_TAG": 1}, [], ["bigquery"])

    # The rest of the sync completed: success, with the cut-short services named for inventory-sync to withhold.
    assert (response["status"], response["withheld_services"]) == ("success", ["bigquery"])


def test_process_reports_services_withheld_during_the_sync(mocker):
    def fake_sync(_sync, _config):
        util.record_withheld_service("bigquery")
        return {"UPDATE_TAG": 1}

    mocker.patch("cartography.sync.run_with_config", side_effect=fake_sync)
    runner = cli.CLI(mocker.Mock(), prog="cartography")

    assert runner.process(_config())["withheld_services"] == ["bigquery"]
    mocker.patch("cartography.sync.run_with_config", return_value={"UPDATE_TAG": 2})
    assert runner.process(_config())["withheld_services"] == []


def _gcp_request():
    return {
        "neo4j": {"uri": "bolt://localhost:7687", "user": "neo4j", "pwd": "x", "connection_lifetime": 200},
        "credentials": {}, "params": {}, "logging": {"mode": "quiet"},
    }


@pytest.mark.parametrize("env, budget", [(None, cli.GCP_SYNC_BUDGET_SECONDS), ("60", 60)])
def test_run_gcp_syncs_under_the_function_budget(mocker, monkeypatch, env, budget):
    if env is None:
        monkeypatch.delenv(cli.GCP_SYNC_BUDGET_ENV, raising=False)
    else:
        monkeypatch.setenv(cli.GCP_SYNC_BUDGET_ENV, env)
    mocker.patch("cartography.util.time.monotonic", return_value=1000.0)
    seen = {}

    def process(_config):
        seen["deadline"] = util._sync_deadline.get()

    mocker.patch.object(cli.CLI, "process", side_effect=process)

    cli.run_gcp(_gcp_request())

    # The 540s Cloud Function timeout kills the worker with no reply; the budget must end well before it.
    assert seen["deadline"] == 1000.0 + budget
    assert cli.GCP_SYNC_BUDGET_SECONDS < 540


def test_process_does_not_carry_failures_into_the_next_sync(mocker):
    mocker.patch("cartography.util.GraphJob.run_from_json", side_effect=[RuntimeError("boom"), None])
    mocker.patch("cartography.util.read_text")

    def fake_sync(_sync, _config):
        util.run_analysis_job_logged("job.json", mocker.Mock(), {})
        return {"UPDATE_TAG": 1}

    mocker.patch("cartography.sync.run_with_config", side_effect=fake_sync)
    runner = cli.CLI(mocker.Mock(), prog="cartography")

    first = runner.process(_config())
    second = runner.process(_config())

    assert [j["job"] for j in first["failed_analysis_jobs"]] == ["job.json"]
    assert second["failed_analysis_jobs"] == []
