from unittest.mock import MagicMock
from unittest.mock import patch

from cartography import util
from cartography.intel.gcp import _sync_single_project
from cartography.intel.gcp import labels_to_clean


@patch("cartography.intel.gcp.GraphDatabase")
@patch("cartography.intel.gcp._services_enabled_on_project")
@patch("cartography.intel.gcp.get_all_regions")
def test_empty_parallel_requests_does_not_raise(mock_regions, mock_enabled, mock_graphdb):
    # Regression: when API-gating drops every requested sync, parallel_requests is empty. min(8, 0) == 0 and
    # ThreadPoolExecutor(max_workers=0) raises ValueError. The empty list must skip the pool entirely.
    mock_regions.return_value = ["us-central1"]
    # compute enabled but not bigquery -> bigquery gets gated out -> parallel_requests == []
    mock_enabled.return_value = {"compute.googleapis.com"}

    common_job_parameters = {"service_labels": []}
    config = MagicMock()
    config.params = {}

    # Must not raise ValueError, and must never build a Neo4j driver for an empty work set.
    _sync_single_project(
        neo4j_session=MagicMock(),
        resources=MagicMock(),
        requested_syncs=["bigquery"],
        project_id="proj-1",
        gcp_update_tag=123,
        common_job_parameters=common_job_parameters,
        config=config,
    )

    mock_graphdb.driver.assert_not_called()


@patch("cartography.intel.gcp.label.cleanup_labels")
@patch("cartography.intel.gcp.GraphDatabase")
@patch("cartography.intel.gcp._services_enabled_on_project")
@patch("cartography.intel.gcp.get_all_regions")
def test_service_out_of_budget_is_withheld_and_keeps_its_labels(
    mock_regions, mock_enabled, mock_graphdb, mock_cleanup_labels,
):
    # cloudanix-web #5338: bigquery ran past the 540s function timeout. Past the budget, a service stops, is reported
    # withheld, and its labels are not cleaned (that would strip those of resources it did not reach); the other
    # services' labels still are.
    mock_regions.return_value = ["us-central1"]
    mock_enabled.return_value = {"bigquery.googleapis.com", "bigtableadmin.googleapis.com"}
    ran = []

    def slow_bigquery(*_args):
        # Raises only if the pool worker sees the caller's deadline (contextvars are not inherited by threads).
        util.check_sync_deadline("bigquery tables")
        ran.append("bigquery")

    def bigtable(*_args):
        ran.append("bigtable")

    common_job_parameters = {"service_labels": ["GCPBigqueryDataset", "GCPBigqueryTable", "GCPBigtableInstance"]}
    config = MagicMock()
    config.params = {}
    functions = {"bigquery": slow_bigquery, "bigtable": bigtable}

    with patch.dict("cartography.intel.gcp.RESOURCE_FUNCTIONS", functions), \
            util.collect_withheld_services() as withheld, util.sync_deadline(1e-9):
        _sync_single_project(
            neo4j_session=MagicMock(),
            resources=MagicMock(),
            requested_syncs=["bigquery", "bigtable"],
            project_id="proj-1",
            gcp_update_tag=123,
            common_job_parameters=common_job_parameters,
            config=config,
        )

    assert withheld == ["bigquery"]
    assert ran == ["bigtable"]
    assert [c.args[2] for c in mock_cleanup_labels.call_args_list] == ["GCPBigtableInstance"]


@patch("cartography.intel.gcp.label.cleanup_labels")
@patch("cartography.intel.gcp.GraphDatabase")
@patch("cartography.intel.gcp._services_enabled_on_project")
@patch("cartography.intel.gcp.get_all_regions")
def test_services_within_budget_clean_their_labels(mock_regions, mock_enabled, mock_graphdb, mock_cleanup_labels):
    mock_regions.return_value = ["us-central1"]
    mock_enabled.return_value = {"bigquery.googleapis.com"}
    config = MagicMock()
    config.params = {}

    with patch.dict("cartography.intel.gcp.RESOURCE_FUNCTIONS", {"bigquery": lambda *_: None}), \
            util.collect_withheld_services() as withheld, util.sync_deadline(420):
        _sync_single_project(
            MagicMock(), MagicMock(), ["bigquery"], "proj-1", 123, {"service_labels": ["bigquerytable"]}, config,
        )

    assert withheld == []
    mock_cleanup_labels.assert_called_once()


def test_a_withheld_service_with_unknown_labels_cleans_none():
    labels = ["GCPBigqueryTable", "GCPInstance"]
    assert labels_to_clean(labels, []) == labels
    assert labels_to_clean(labels, ["bigquery"]) == ["GCPInstance"]
    assert labels_to_clean(labels, ["bigquery", "compute"]) == []
