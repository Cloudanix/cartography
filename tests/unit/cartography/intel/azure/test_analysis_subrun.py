from unittest.mock import MagicMock

import cartography.intel.azure as azure

TENANT = {"tenantId": "tenant-1", "defaultDomain": "example.onmicrosoft.com"}
SUBSCRIPTIONS = [{"subscriptionId": "sub-1"}]


def _sync(mocker, monkeypatch, requested_syncs):
    """Run _sync_multiple_subscriptions; return (analysis jobs run, tag.sync mock)."""
    monkeypatch.setenv("LOCAL_RUN", "1")
    jobs = []
    mocker.patch.dict(azure.RESOURCE_FUNCTIONS, {"compute": MagicMock()})
    mocker.patch.object(azure.subscription, "sync")
    tag_sync = mocker.patch.object(azure.tag, "sync")
    mocker.patch.object(azure.post_sync, "run_analysis_job", side_effect=lambda name, *_: jobs.append(name))
    mocker.patch.object(azure.exposure_layers, "run", side_effect=lambda *_: jobs.append("exposure_layers"))

    azure._sync_multiple_subscriptions(
        MagicMock(), MagicMock(tenant_id="tenant-1"), TENANT, SUBSCRIPTIONS, requested_syncs, 42,
        {"WORKSPACE_ID": "ws-1"}, MagicMock(),
    )
    return jobs, tag_sync


def test_analysis_subrun_skips_the_resource_and_tag_syncs(mocker, monkeypatch):
    # tag.sync lists resource groups and cleans up what it did not refresh: on an analysis subrun (newer update
    # tag) an ARM error there would delete the groups the resource subruns wrote.
    jobs, tag_sync = _sync(mocker, monkeypatch, ["analysis"])

    tag_sync.assert_not_called()
    azure.RESOURCE_FUNCTIONS["compute"].assert_not_called()
    assert "exposure_layers" in jobs


def test_analysis_with_resource_syncs_logs_no_unknown_sync(mocker, monkeypatch, caplog):
    jobs, tag_sync = _sync(mocker, monkeypatch, ["compute", "analysis"])

    tag_sync.assert_called_once()
    assert "exposure_layers" in jobs
    assert "does not exist" not in caplog.text
