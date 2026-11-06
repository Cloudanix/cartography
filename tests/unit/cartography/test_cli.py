from types import SimpleNamespace

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
