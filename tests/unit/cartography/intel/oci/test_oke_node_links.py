from unittest.mock import MagicMock
from unittest.mock import patch

import cartography.intel.oci
from cartography.intel.oci import oke

PARAMS = {"WORKSPACE_ID": "ws-1", "OCI_TENANCY_ID": "ocid1.tenancy.oc1..t", "UPDATE_TAG": 42}


def _run_captured_write(session):
    """run_write_query hands a tx function to execute_write; run it against a mock tx."""
    tx = MagicMock()
    session.execute_write.call_args.args[0](tx)
    return tx.run.call_args


def test_load_node_pools_stores_worker_ids_without_linking_instances():
    session = MagicMock()
    pools = [{"id": "pool-1", "ocid": "pool-1", "cluster_id": "cl-1", "nodes": [{"ocid": "inst-1"}]}]

    oke.load_node_pools(session, pools, "comp-1", 42)

    # one batched write for the pools; instance links wait for sync_oke_node_links
    session.execute_write.assert_called_once()
    query = session.execute_write.call_args.args[1]
    assert "np.node_ids = [n IN coalesce(p.nodes, []) WHERE n.ocid IS NOT NULL | n.ocid]" in query
    assert "OCIInstance" not in query


def test_link_oke_nodes_is_scoped_to_workspace_and_tenancy():
    session = MagicMock()

    oke.link_oke_nodes(session, PARAMS)

    call = _run_captured_write(session)
    query = call.args[0]
    assert "(:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:OCITenancy{id: $OCI_TENANCY_ID})" in query
    assert "-[:OWNER]->(:OCICompartment)-[:RESOURCE]->(np:OCIOKENodePool)" in query
    assert "MERGE (np)-[r:HAS_NODE]->(i)" in query
    assert "MATCH (cl:OCIOKECluster)-[:HAS_NODE_POOL]->(np)" in query
    assert "MERGE (cl)-[r2:HAS_NODE]->(i)" in query
    assert "CONTAINS_NODE" not in query
    assert call.kwargs == PARAMS


def test_sync_oke_node_links_links_before_cleanup():
    order = []
    with patch.object(oke, "link_oke_nodes", side_effect=lambda *_: order.append("link")), \
            patch.object(oke, "cleanup_oke_node_links", side_effect=lambda *_: order.append("cleanup")):
        oke.sync_oke_node_links(MagicMock(), PARAMS)

    assert order == ["link", "cleanup"]


def _sync_compartments(requested, link_side_effect=None):
    """Run _sync_multiple_compartments over two compartments with stubs; return the call order."""
    order = []
    with patch.object(cartography.intel.oci, "_initialize_resources"), \
            patch.object(
                cartography.intel.oci,
                "_sync_one_compartment",
                side_effect=lambda _s, _r, compartment_id, *_: order.append(compartment_id),
            ), \
            patch.object(
                cartography.intel.oci.tags, "cleanup_tags", side_effect=lambda *_: order.append("tags"),
            ), \
            patch.object(
                cartography.intel.oci.oke,
                "sync_oke_node_links",
                side_effect=link_side_effect or (lambda *_: order.append("link")),
            ):
        cartography.intel.oci._sync_multiple_compartments(
            MagicMock(),
            {},
            PARAMS["OCI_TENANCY_ID"],
            [{"compartmentId": "comp-a"}, {"compartmentId": "comp-b"}],
            requested,
            42,
            dict(PARAMS),
            [],
        )
    return order


def test_tenancy_sync_links_oke_nodes_after_every_compartment():
    assert _sync_compartments(["oke", "compute"]) == ["comp-a", "comp-b", "link", "tags"]


def test_tenancy_sync_skips_oke_node_links_when_neither_requested():
    assert "link" not in _sync_compartments(["storage"])


def test_tenancy_sync_continues_when_oke_node_links_fail():
    def _boom(*_):
        raise RuntimeError("neo4j down")

    assert _sync_compartments(["oke"], link_side_effect=_boom) == ["comp-a", "comp-b", "tags"]
