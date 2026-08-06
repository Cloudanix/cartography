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


class TestLoadGcpForwardingRules:
    def test_batches_and_partitions_attachments(self):
        session = MagicMock()
        subnet_rule = {
            "partial_uri": "projects/p1/regions/us-east1/forwardingRules/a",
            "ip_address": "10.0.0.9",
            "ip_protocol": "TCP",
            "load_balancing_scheme": "INTERNAL",
            "name": "a",
            "project_id": "p1",
            "self_link": "https://selflink/a",
            "target": "projects/p1/targets/t1",
            "subnetwork": "https://subnet",
            "subnetwork_partial_uri": "projects/p1/regions/us-east1/subnetworks/default",
            "network": "https://net",
            "network_partial_uri": "projects/p1/global/networks/default",
        }
        vpc_rule = {
            "partial_uri": "projects/p1/regions/us-east1/forwardingRules/b",
            "ip_address": "10.0.0.10",
            "ip_protocol": "TCP",
            "load_balancing_scheme": "EXTERNAL",
            "name": "b",
            "project_id": "p1",
            "self_link": "https://selflink/b",
            "target": "projects/p1/targets/t2",
            "network": "https://net",
            "network_partial_uri": "projects/p1/global/networks/default",
        }

        compute.load_gcp_forwarding_rules(session, [subnet_rule, vpc_rule], TEST_UPDATE_TAG)

        # one write for the rules, one for the subnet attachment batch, one for the vpc batch
        assert session.execute_write.call_count == 3
        main, subnet_attach, vpc_attach = session.execute_write.call_args_list
        assert main.kwargs["DictList"] == [subnet_rule, vpc_rule]
        assert subnet_attach.kwargs["DictList"] == [subnet_rule]
        assert "GCPSubnet" in subnet_attach.args[1]
        assert vpc_attach.kwargs["DictList"] == [vpc_rule]
        assert "GCPVpc" in vpc_attach.args[1]

    def test_empty_list_writes_nothing(self):
        session = MagicMock()
        compute.load_gcp_forwarding_rules(session, [], TEST_UPDATE_TAG)
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
