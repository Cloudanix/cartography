from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.gcp import _sync_single_project


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
