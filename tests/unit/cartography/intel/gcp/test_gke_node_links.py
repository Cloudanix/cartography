from unittest.mock import MagicMock
from unittest.mock import patch

import cartography.intel.gcp
from cartography.intel.gcp import compute

PARAMS = {"GCP_PROJECT_ID": "proj-1", "UPDATE_TAG": 42, "service_labels": []}


def _run_captured_write(session):
    """run_write_query hands a tx function to execute_write; run it against a mock tx."""
    tx = MagicMock()
    session.execute_write.call_args.args[0](tx)
    return tx.run.call_args


def test_link_gke_nodes_is_scoped_to_the_project():
    session = MagicMock()

    compute.link_gke_nodes(session, PARAMS)

    call = _run_captured_write(session)
    query = call.args[0]
    assert "MATCH (p:GCPProject{id: $GCP_PROJECT_ID})-[:RESOURCE]->(i:GCPInstance)" in query
    # cluster must belong to the same project and is matched by its full id
    assert "MATCH (p)-[:RESOURCE]->(c:GKECluster{" in query
    assert "'projects/' + p.id + '/locations/' + i.region + '/clusters/' + i.gke_cluster_name" in query
    assert "(c)-[:HAS_NODE_POOL]->(pool:GKENodePool{id: c.id + '/nodePools/' + i.gke_node_pool_name})" in query
    assert call.kwargs == {"GCP_PROJECT_ID": "proj-1", "UPDATE_TAG": 42}


def test_sync_gke_node_links_links_before_cleanup():
    order = []
    with patch.object(compute, "link_gke_nodes", side_effect=lambda *_: order.append("link")), \
            patch.object(compute, "cleanup_gke_compute_links", side_effect=lambda *_: order.append("cleanup")):
        compute.sync_gke_node_links(MagicMock(), PARAMS)

    assert order == ["link", "cleanup"]


def _sync_project(requested, link_side_effect=None):
    """Run _sync_single_project sequentially with stub services; return the call order."""
    order = []
    services = {
        "compute": lambda *_: order.append("compute"),
        "gke": lambda *_: order.append("gke"),
    }
    with patch.dict("os.environ", {"LOCAL_RUN": "1"}), \
            patch.object(cartography.intel.gcp, "RESOURCE_FUNCTIONS", services), \
            patch.object(cartography.intel.gcp, "get_all_regions", return_value=["us-central1"]), \
            patch.object(
                cartography.intel.gcp.compute,
                "sync_gke_node_links",
                side_effect=link_side_effect or (lambda *_: order.append("link")),
            ):
        config = MagicMock()
        config.params = {}
        cartography.intel.gcp._sync_single_project(
            neo4j_session=MagicMock(),
            resources=MagicMock(),
            requested_syncs=requested,
            project_id="proj-1",
            gcp_update_tag=42,
            common_job_parameters=dict(PARAMS),
            config=config,
        )
    return order


def test_project_sync_links_gke_nodes_after_both_syncs():
    order = _sync_project(["gke", "compute"])

    assert order.index("link") > order.index("gke")
    assert order.index("link") > order.index("compute")


def test_project_sync_skips_gke_node_links_when_neither_requested():
    assert "link" not in _sync_project([])


def test_project_sync_continues_when_gke_node_links_fail():
    def _boom(*_):
        raise RuntimeError("neo4j down")

    # must not raise
    assert _sync_project(["compute"], link_side_effect=_boom) == ["compute"]
