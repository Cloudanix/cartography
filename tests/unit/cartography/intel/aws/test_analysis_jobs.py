import os
from unittest.mock import MagicMock

import cartography.intel.aws

ANALYSIS_JOB_DIR = os.path.join(os.path.dirname(cartography.__file__), 'data', 'jobs', 'analysis')


def _analysis_jobs_run_by_account_sync(mocker, monkeypatch, requested_syncs=(), params=None):
    """
    Run _sync_one_account for requested_syncs (none: everything) with request params; return the analysis job names it
    runs, plus "exposure_layers" when it runs the layers.
    """
    monkeypatch.setenv("LOCAL_RUN", "1")
    jobs = []
    mocker.patch.dict(cartography.intel.aws.RESOURCE_FUNCTIONS, {name: MagicMock() for name in requested_syncs})
    mocker.patch.object(cartography.intel.aws, "_resolve_sync_regions", return_value=["us-east-1"])
    mocker.patch.object(cartography.intel.aws, "_build_aws_sync_kwargs", return_value={})
    mocker.patch.object(cartography.intel.aws, "run_cleanup_job")
    mocker.patch.object(cartography.intel.post_sync, "run_analysis_job", side_effect=lambda name, *_: jobs.append(name))
    mocker.patch.object(
        cartography.intel.aws.exposure_layers, "run", side_effect=lambda *_: jobs.append("exposure_layers"),
    )
    config = MagicMock()
    config.aws_excluded_regions = None
    config.refresh_entitlements = False
    config.params = params or {}

    cartography.intel.aws._sync_one_account(
        MagicMock(), MagicMock(), "111111111111", 42, {"AWS_ID": "111111111111"}, ["us-east-1"], list(requested_syncs),
        creds={}, config=config,
    )
    return jobs


def _phase_jobs(phases):
    return [*phases.link, *phases.exposure, *phases.posture]


def test_account_sync_runs_the_phases_in_order_then_the_layers_before_posture(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch, ["analysis"])

    phases = cartography.intel.aws.AWS_PHASES
    assert jobs == [*phases.link, *phases.exposure, "exposure_layers", *phases.posture]


def test_group_subrun_skips_the_analysis_when_its_run_defers_it(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch, ["rds"], params={"deferAnalysis": True})

    assert jobs == []


def test_group_subrun_without_defer_keeps_running_the_jobs_but_not_the_layers(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch, ["rds"])

    assert jobs == _phase_jobs(cartography.intel.aws.AWS_PHASES)


def test_account_sync_does_not_run_the_duplicate_s3acl_job(mocker, monkeypatch):
    # aws_s3_asset_exposure.json sets the same S3 anonymous_access properties on the workspace's
    # Organization path; the s3acl job used the direct Workspace->Account path, which matches nothing.
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert "aws_s3_asset_exposure.json" in jobs
    assert "aws_s3acl_analysis.json" not in jobs


def test_account_sync_runs_the_appsync_exposure_job(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert "aws_appsync_asset_exposure.json" in jobs


def test_account_sync_runs_the_dms_exposure_job(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert "aws_dms_asset_exposure.json" in jobs


def test_account_sync_runs_the_beanstalk_exposure_job_after_the_elb_and_instance_jobs(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    beanstalk = jobs.index("aws_elasticbeanstalk_asset_exposure.json")
    assert beanstalk > jobs.index("aws_ec2_elb_asset_exposure.json")
    assert beanstalk > jobs.index("aws_ec2_instance_asset_exposure.json")


def test_every_analysis_job_run_by_account_sync_exists(mocker, monkeypatch):
    jobs = [job for job in _analysis_jobs_run_by_account_sync(mocker, monkeypatch) if job != "exposure_layers"]

    assert jobs
    assert [job for job in jobs if not os.path.exists(os.path.join(ANALYSIS_JOB_DIR, job))] == []
