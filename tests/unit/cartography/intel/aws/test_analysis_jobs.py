import json
import os
import re
from unittest.mock import MagicMock

import cartography.intel.aws

ANALYSIS_JOB_DIR = os.path.join(os.path.dirname(cartography.__file__), 'data', 'jobs', 'analysis')


def _analysis_jobs_run_by_account_sync(mocker, monkeypatch, requested_syncs=()):
    """
    Run _sync_one_account for requested_syncs (none: everything); return the analysis job names it runs, plus
    "exposure_layers" when it runs the layers.
    """
    monkeypatch.setenv("LOCAL_RUN", "1")
    jobs = []
    # Stub only resource syncs: "analysis" must hit the real RESOURCE_FUNCTIONS lookup, as in production.
    mocker.patch.dict(
        cartography.intel.aws.RESOURCE_FUNCTIONS,
        {name: MagicMock() for name in requested_syncs if name != "analysis"},
    )
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
    config.params = {}

    cartography.intel.aws._sync_one_account(
        MagicMock(), MagicMock(), "111111111111", 42, {"AWS_ID": "111111111111"}, ["us-east-1"], list(requested_syncs),
        creds={}, config=config,
    )
    return jobs


def test_account_sync_runs_the_phases_in_order_then_the_layers_before_posture(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch, ["analysis"])

    phases = cartography.intel.aws.AWS_PHASES
    assert jobs == [*phases.link, *phases.exposure, "exposure_layers", *phases.posture]


def test_group_subrun_runs_no_analysis(mocker, monkeypatch):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch, ["rds"])

    assert jobs == []


def test_analysis_subrun_calls_no_api_and_logs_no_unknown_sync(mocker, monkeypatch, caplog):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch, ["analysis"])

    assert "exposure_layers" in jobs
    # No DescribeVpcs region probe, resource sync or cleanup: it reads what the group subruns wrote.
    cartography.intel.aws._resolve_sync_regions.assert_not_called()
    cartography.intel.aws.run_cleanup_job.assert_not_called()
    assert "does not exist" not in caplog.text


def test_analysis_with_resource_syncs_logs_no_unknown_sync(mocker, monkeypatch, caplog):
    jobs = _analysis_jobs_run_by_account_sync(mocker, monkeypatch, ["rds", "analysis"])

    assert "exposure_layers" in jobs
    assert "does not exist" not in caplog.text


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


# Properties an AWS sync module computes for every node of the label on each run (it clears / re-sets them itself).
# The post-sync analysis subrun runs the exposure jobs WITHOUT a sync before it, and its inventory export is the last
# one the console loads: an analysis job that REMOVEs one of these drops it from the asset until the next sync.
SYNC_OWNED_PROPERTIES = {
    "S3Bucket": {"anonymous_access", "anonymous_actions"},  # s3.load_s3_details (+ cleanup aws_s3_details.json)
    "APIGatewayRestAPI": {"anonymous_access", "anonymous_actions"},  # apigateway._set_default_values
    "AWSLambda": {"anonymous_access", "anonymous_actions"},  # lambda_function.load_lambda_functions
    "KMSKey": {"anonymous_access", "anonymous_actions"},  # kms._load_kms_key_policies / _set_default_values
}
_NODE_BINDING = re.compile(r"\((\w+):(\w+)")
_REMOVE_CLAUSE = re.compile(r"\bREMOVE\s+(.+?)(?=\s+(?:return|RETURN|WITH|SET)\b|;|$)", re.DOTALL)
_PROPERTY = re.compile(r"\b(\w+)\.(\w+)")


def _removed_properties(query):
    """(label, property) pairs a statement REMOVEs, resolving each variable to the label it is bound to."""
    labels = {var: label for var, label in _NODE_BINDING.findall(query)}
    return {
        (labels.get(var, "?"), prop)
        for clause in _REMOVE_CLAUSE.findall(query)
        for var, prop in _PROPERTY.findall(clause)
    }


def test_no_analysis_job_removes_a_property_the_sync_owns():
    offending = []
    for name in sorted(os.listdir(ANALYSIS_JOB_DIR)):
        if not (name.startswith("aws_") and name.endswith(".json")):
            continue
        with open(os.path.join(ANALYSIS_JOB_DIR, name)) as f:
            statements = json.load(f)["statements"]
        for statement in statements:
            for label, prop in _removed_properties(statement["query"]):
                if prop in SYNC_OWNED_PROPERTIES.get(label, set()):
                    offending.append((name, label, prop))

    assert offending == []


def test_removed_properties_resolves_the_bound_label():
    query = "MATCH (b:S3Bucket)<-[:RESOURCE]-(a:AWSAccount) REMOVE b.anonymous_access_type, b.publicContext RETURN 1"

    assert _removed_properties(query) == {("S3Bucket", "anonymous_access_type"), ("S3Bucket", "publicContext")}


def test_every_analysis_job_run_by_account_sync_exists(mocker, monkeypatch):
    jobs = [job for job in _analysis_jobs_run_by_account_sync(mocker, monkeypatch) if job != "exposure_layers"]

    assert jobs
    assert [job for job in jobs if not os.path.exists(os.path.join(ANALYSIS_JOB_DIR, job))] == []
