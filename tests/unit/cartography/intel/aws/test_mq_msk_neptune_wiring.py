from cartography.intel.aws import mq
from cartography.intel.aws import msk
from cartography.intel.aws.resources import parse_and_validate_aws_requested_syncs
from cartography.intel.aws.resources import RESOURCE_FUNCTIONS
from tests.unit.cartography.intel.aws.test_analysis_jobs import _analysis_jobs_run_by_account_sync


def test_mq_and_msk_are_requestable_service_names():
    # cloudanix-web sends these names in the run's service list (AWS.INVENTORY.SERVICES).
    assert parse_and_validate_aws_requested_syncs('rds, mq, msk') == ['rds', 'mq', 'msk']
    assert (RESOURCE_FUNCTIONS['mq'], RESOURCE_FUNCTIONS['msk']) == (mq.sync, msk.sync)


def test_account_sync_runs_the_mq_and_msk_exposure_jobs(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert "aws_mq_broker_asset_exposure.json" in jobs
    assert "aws_msk_cluster_asset_exposure.json" in jobs


def test_account_sync_runs_the_neptune_exposure_job_after_the_rds_job(mocker, monkeypatch):
    # Neptune clusters are exposed through their RDSInstance members, which the RDS job judges.
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch)

    assert jobs.index("aws_neptune_cluster_asset_exposure.json") > jobs.index("aws_rds_asset_exposure.json")
