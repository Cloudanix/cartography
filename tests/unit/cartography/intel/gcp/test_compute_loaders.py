"""
Unit tests for the batched (UNWIND $DictList) loaders in cartography.intel.gcp.compute.

These verify the perf plan Phase 3.1 migration: one write transaction per batch instead
of one per row, with row payloads built correctly. A MagicMock session records the
execute_write calls issued by load_graph_data.
"""
from unittest.mock import MagicMock

from cartography.intel.gcp import compute

TEST_UPDATE_TAG = 123456789

VPC_A = {
    "partial_uri": "projects/p1/global/networks/default",
    "name": "default",
    "self_link": "https://www.googleapis.com/compute/v1/projects/p1/global/networks/default",
    "project_id": "p1",
    "auto_create_subnetworks": True,
    "description": "Default VPC",
    "routing_config_routing_mode": "REGIONAL",
    "region": "us-east1",
    "consolelink": "https://console.cloud.google.com/networking",
    "isDefault": True,
}

SUBNET_A = {
    "partial_uri": "projects/p1/regions/us-east1/subnetworks/default",
    "name": "default",
    "self_link": "https://www.googleapis.com/compute/v1/projects/p1/regions/us-east1/subnetworks/default",
    "project_id": "p1",
    "region": "us-east1",
    "gateway_address": "10.0.0.1",
    "ip_cidr_range": "10.0.0.0/20",
    "private_ip_google_access": False,
    "vpc_partial_uri": "projects/p1/global/networks/default",
    "vpc_self_link": "https://www.googleapis.com/compute/v1/projects/p1/global/networks/default",
    "consolelink": "https://console.cloud.google.com/networking",
    "isDefault": True,
}


class TestLoadGcpVpcs:
    def test_single_batched_write(self):
        session = MagicMock()
        vpcs = [VPC_A, {**VPC_A, "partial_uri": "projects/p1/global/networks/other", "name": "other"}]

        compute.load_gcp_vpcs(session, vpcs, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert "UNWIND $DictList AS item" in call.args[1]
        assert call.kwargs["DictList"] == vpcs
        assert call.kwargs["gcp_update_tag"] == TEST_UPDATE_TAG

    def test_empty_list_writes_nothing(self):
        session = MagicMock()
        compute.load_gcp_vpcs(session, [], TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()


class TestLoadGcpSubnets:
    def test_single_batched_write(self):
        session = MagicMock()
        subnets = [SUBNET_A]

        compute.load_gcp_subnets(session, subnets, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert "UNWIND $DictList AS item" in call.args[1]
        assert call.kwargs["DictList"] == subnets
        assert call.kwargs["gcp_update_tag"] == TEST_UPDATE_TAG

    def test_empty_list_writes_nothing(self):
        session = MagicMock()
        compute.load_gcp_subnets(session, [], TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()
