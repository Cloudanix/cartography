from unittest.mock import MagicMock

import cartography.intel.aws
from cartography.intel.aws.ec2 import instances

PARAMS = {"WORKSPACE_ID": "ws-1", "AWS_ID": "111111111111", "UPDATE_TAG": 42}


def _run_captured_write(session):
    """run_write_query hands a tx function to execute_write; run it against a mock tx."""
    tx = MagicMock()
    session.execute_write.call_args.args[0](tx)
    return tx.run.call_args


def test_link_ec2_to_eks_is_scoped_to_workspace_account_and_region():
    session = MagicMock()

    instances.link_ec2_to_eks(session, PARAMS)

    call = _run_captured_write(session)
    query = call.args[0]
    assert "(:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(a:AWSAccount{id: $AWS_ID})" in query
    assert "(a)-[:RESOURCE]->(c:EKSCluster{name: i.eksclustername, region: i.region})" in query
    assert "(c)<-[:ASSOCIATED_WITH]-(ng:EKSClusterNodeGroup{name: i.eksnodegroupname})" in query
    assert call.kwargs == {"WORKSPACE_ID": "ws-1", "AWS_ID": "111111111111", "UPDATE_TAG": 42}


def test_sync_eks_node_links_links_before_cleanup(mocker):
    order = []
    mocker.patch.object(instances, "link_ec2_to_eks", side_effect=lambda *_: order.append("link"))
    mocker.patch.object(instances, "cleanup_eks_node_links", side_effect=lambda *_: order.append("cleanup"))

    instances.sync_eks_node_links(MagicMock(), PARAMS)

    assert order == ["link", "cleanup"]


def _sync_account(mocker, monkeypatch, requested, link_side_effect=None):
    """Run _sync_one_account sequentially with stub services; return the call order."""
    monkeypatch.setenv("LOCAL_RUN", "1")
    order = []
    mocker.patch.dict(
        cartography.intel.aws.RESOURCE_FUNCTIONS,
        {
            "ec2:instance": lambda **_: order.append("ec2:instance"),
            "eks": lambda **_: order.append("eks"),
        },
    )
    mocker.patch.object(cartography.intel.aws, "_resolve_sync_regions", return_value=["us-east-1"])
    mocker.patch.object(cartography.intel.aws, "_build_aws_sync_kwargs", return_value={})
    mocker.patch.object(cartography.intel.aws, "run_cleanup_job")
    mocker.patch.object(
        cartography.intel.aws, "run_analysis_job", side_effect=lambda *_: order.append("analysis"),
    )
    mocker.patch.object(
        cartography.intel.aws,
        "sync_eks_node_links",
        side_effect=link_side_effect or (lambda *_: order.append("link")),
    )
    config = MagicMock()
    config.aws_excluded_regions = None
    config.refresh_entitlements = False

    cartography.intel.aws._sync_one_account(
        MagicMock(), MagicMock(), "111111111111", 42, dict(PARAMS), ["us-east-1"], requested,
        creds={}, config=config,
    )
    return order


def test_account_sync_links_eks_nodes_after_both_syncs(mocker, monkeypatch):
    order = _sync_account(mocker, monkeypatch, ["eks", "ec2:instance"])

    assert order.index("link") > order.index("eks")
    assert order.index("link") > order.index("ec2:instance")
    assert order.index("link") < order.index("analysis")


def test_account_sync_skips_eks_node_links_when_neither_requested(mocker, monkeypatch):
    order = _sync_account(mocker, monkeypatch, [])

    assert "link" not in order


def test_account_sync_continues_when_eks_node_links_fail(mocker, monkeypatch):
    def _boom(*_):
        raise RuntimeError("neo4j down")

    order = _sync_account(mocker, monkeypatch, ["ec2:instance"], link_side_effect=_boom)

    assert "analysis" in order
