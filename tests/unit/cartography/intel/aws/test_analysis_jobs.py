import os
from unittest.mock import MagicMock

import cartography.intel.aws

ANALYSIS_JOB_DIR = os.path.join(os.path.dirname(cartography.__file__), 'data', 'jobs', 'analysis')


def _analysis_jobs_run_by_account_sync(mocker, monkeypatch):
    """Run _sync_one_account with no services requested; return the analysis job names it runs."""
    monkeypatch.setenv("LOCAL_RUN", "1")
    jobs = []
    mocker.patch.object(cartography.intel.aws, "_resolve_sync_regions", return_value=["us-east-1"])
    mocker.patch.object(cartography.intel.aws, "_build_aws_sync_kwargs", return_value={})
    mocker.patch.object(cartography.intel.aws, "run_cleanup_job")
    mocker.patch.object(cartography.intel.aws, "run_analysis_job", side_effect=lambda name, *_: jobs.append(name))
    config = MagicMock()
    config.aws_excluded_regions = None
    config.refresh_entitlements = False

    cartography.intel.aws._sync_one_account(
        MagicMock(), MagicMock(), "111111111111", 42, {"AWS_ID": "111111111111"}, ["us-east-1"], [],
        creds={}, config=config,
    )
    return jobs


def test_account_sync_does_not_run_the_duplicate_s3acl_job(mocker, monkeypatch):
    # aws_s3_asset_exposure.json sets the same S3 anonymous_access properties on the workspace's
    # Organization path; the s3acl job used the direct Workspace->Account path, which matches nothing.
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert "aws_s3_asset_exposure.json" in jobs
    assert "aws_s3acl_analysis.json" not in jobs


def test_account_sync_runs_the_mq_exposure_job(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert "aws_mq_broker_asset_exposure.json" in jobs


def test_account_sync_runs_the_msk_exposure_job(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert "aws_msk_cluster_asset_exposure.json" in jobs


def test_account_sync_runs_the_neptune_exposure_job_after_the_rds_job(mocker, monkeypatch):
    # Neptune clusters are exposed through their RDSInstance members, which the RDS job judges.
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert jobs.index("aws_neptune_cluster_asset_exposure.json") > jobs.index("aws_rds_asset_exposure.json")


def test_every_analysis_job_run_by_account_sync_exists(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert jobs
    assert [job for job in jobs if not os.path.exists(os.path.join(ANALYSIS_JOB_DIR, job))] == []
