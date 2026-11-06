from unittest.mock import MagicMock
from unittest.mock import patch

import cartography.intel.azure
from cartography.intel.azure import aks
from cartography.intel.azure import compute

PARAMS = {
    "WORKSPACE_ID": "ws-1",
    "AZURE_TENANT_ID": "tenant-1",
    "AZURE_SUBSCRIPTION_ID": "sub-1",
    "UPDATE_TAG": 42,
}


def _captured_writes(session):
    """run_write_query hands a tx function to execute_write; run each against a mock tx."""
    calls = []
    for write in session.execute_write.call_args_list:
        tx = MagicMock()
        write.args[0](tx)
        calls.append(tx.run.call_args)
    return calls


def test_link_compute_to_aks_is_scoped_to_workspace_tenant_and_subscription():
    session = MagicMock()

    compute.link_compute_to_aks(session, PARAMS)

    calls = _captured_writes(session)
    # one labelled query per AKS node type
    assert [c.args[0].count("(node:AzureVirtualMachine)") for c in calls] == [1, 0]
    assert [c.args[0].count("(node:AzureVirtualMachineScaleSet)") for c in calls] == [0, 1]
    for call in calls:
        query = call.args[0]
        assert "(:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AzureTenant{id: $AZURE_TENANT_ID})" in query
        assert "(s:AzureSubscription{id: $AZURE_SUBSCRIPTION_ID})" in query
        assert "MATCH (s)-[:RESOURCE]->(c:AzureCluster)" in query
        assert "(c)-[:HAS]->(p:AzureClusterAgentPool)" in query
        assert call.kwargs == PARAMS


def test_link_compute_to_aks_matches_node_resource_group_and_tags_case_insensitively():
    session = MagicMock()

    compute.link_compute_to_aks(session, PARAMS)

    query = _captured_writes(session)[0].args[0]
    assert "toLower(node.resourcegroup) = c.node_resource_group" in query
    assert "toLower(node.aks_cluster_rg) = toLower(c.resourcegroup)" in query
    assert "toLower(p.name) = toLower(node.aks_pool_name)" in query


def test_sync_aks_node_links_links_before_cleanup():
    order = []
    with patch.object(compute, "link_compute_to_aks", side_effect=lambda *_: order.append("link")), \
            patch.object(compute, "cleanup_aks_compute_links", side_effect=lambda *_: order.append("cleanup")):
        compute.sync_aks_node_links(MagicMock(), PARAMS)

    assert order == ["link", "cleanup"]


def _sync_subscription(requested, link_side_effect=None):
    """Run _sync_one_subscription sequentially with stub services; return the call order."""
    order = []
    services = {
        "aks": lambda *_: order.append("aks"),
        "compute": lambda *_: order.append("compute"),
    }
    with patch.dict("os.environ", {"LOCAL_RUN": "1"}), \
            patch.object(cartography.intel.azure, "RESOURCE_FUNCTIONS", services), \
            patch.object(cartography.intel.azure.tag, "sync", side_effect=lambda *_: order.append("tag")), \
            patch.object(
                cartography.intel.azure.compute,
                "sync_aks_node_links",
                side_effect=link_side_effect or (lambda *_: order.append("link")),
            ):
        credentials = MagicMock()
        credentials.tenant_id = "tenant-1"
        config = MagicMock()
        config.params = {"regions": None}
        cartography.intel.azure._sync_one_subscription(
            neo4j_session=MagicMock(),
            credentials=credentials,
            subscription_id="sub-1",
            tenant={"defaultDomain": "test.onmicrosoft.com"},
            requested_syncs=requested,
            update_tag=42,
            common_job_parameters=dict(PARAMS),
            config=config,
        )
    return order


def test_subscription_sync_links_aks_nodes_after_both_syncs_and_before_tags():
    order = _sync_subscription(["aks", "compute"])

    assert order.index("link") > order.index("aks")
    assert order.index("link") > order.index("compute")
    assert order.index("link") < order.index("tag")


def test_subscription_sync_skips_aks_node_links_when_neither_requested():
    assert "link" not in _sync_subscription([])


def test_subscription_sync_continues_when_aks_node_links_fail():
    def _boom(*_):
        raise RuntimeError("neo4j down")

    assert "tag" in _sync_subscription(["compute"], link_side_effect=_boom)


def test_load_aks_clusters_stores_lowercased_node_resource_group():
    cluster = {"id": "/subscriptions/sub-1/resourceGroups/RG/x", "node_resource_group": "MC_RG_Cluster_eastus"}
    tx = MagicMock()

    aks._load_aks_managed_clusters_tx(tx, "sub-1", [cluster], 42)

    query = tx.run.call_args_list[0].args[0]
    assert "a.node_resource_group = toLower(aks.node_resource_group)" in query
