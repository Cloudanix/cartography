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


INSTANCE = {
    "partial_uri": "projects/p1/zones/z1/instances/vm-1",
    "project_id": "p1",
    "region": "us-east1",
    "tags": {"items": ["web", "db"]},
    "networkInterfaces": [
        {
            "name": "nic0",
            "network": "https://net/default",
            "consolelink": "https://console/nic0",
            "subnet_partial_uri": "projects/p1/regions/us-east1/subnetworks/default",
            "vpc_partial_uri": "projects/p1/global/networks/default",
            "accessConfigs": [
                {"type": "ONE_TO_ONE_NAT", "name": "External NAT", "natIP": "34.1.2.3"},
            ],
        },
    ],
    "serviceAccounts": [{"email": "sa@p1.iam.gserviceaccount.com"}],
    "gke_cluster_name": "prod",
    "gke_node_pool_name": "pool-1",
}

NIC_ID = "projects/p1/zones/z1/instances/vm-1/networkinterfaces/nic0"


class TestInstanceRowBuilders:
    def test_tag_rows_are_instance_x_tag_x_nic(self):
        rows = compute._build_instance_tag_rows([INSTANCE])
        assert len(rows) == 2  # 2 tags x 1 nic
        assert rows[0]["instance_id"] == INSTANCE["partial_uri"]
        assert rows[0]["vpc_partial_uri"] == "projects/p1/global/networks/default"
        assert {r["tag_value"] for r in rows} == {"web", "db"}
        assert all(r["tag_id"] == f"projects/p1/global/networks/default/tags/{r['tag_value']}" for r in rows)

    def test_nic_rows(self):
        rows = compute._build_nic_rows([INSTANCE])
        assert rows == [{
            "instance_id": INSTANCE["partial_uri"],
            "nic_id": NIC_ID,
            "network": "https://net/default",
            "name": "nic0",
            "consolelink": "https://console/nic0",
            "subnet_partial_uri": "projects/p1/regions/us-east1/subnetworks/default",
        }]

    def test_access_config_rows(self):
        rows = compute._build_access_config_rows([INSTANCE])
        assert rows == [{
            "nic_id": NIC_ID,
            "access_config_id": f"{NIC_ID}/accessconfigs/ONE_TO_ONE_NAT",
            "type": "ONE_TO_ONE_NAT",
            "name": "External NAT",
            "consolelink": None,
            "nat_ip": "34.1.2.3",
            "set_public_ptr": None,
            "public_ptr_domain_name": None,
            "network_tier": None,
        }]

    def test_service_account_rows(self):
        rows = compute._build_service_account_rows([INSTANCE])
        assert rows == [{"instance_id": INSTANCE["partial_uri"], "email": "sa@p1.iam.gserviceaccount.com"}]

    def test_gke_rows_only_for_gke_instances(self):
        plain = {**INSTANCE, "gke_cluster_name": None, "gke_node_pool_name": None}
        cluster_only = {**INSTANCE, "gke_node_pool_name": None}

        cluster_rows = compute._build_gke_cluster_link_rows([INSTANCE, plain, cluster_only])
        pool_rows = compute._build_gke_node_pool_link_rows([INSTANCE, plain, cluster_only])

        assert len(cluster_rows) == 2
        assert cluster_rows[0] == {
            "cluster_id": "projects/p1/locations/us-east1/clusters/prod",
            "instance_id": INSTANCE["partial_uri"],
        }
        assert pool_rows == [{
            "node_pool_id": "projects/p1/locations/us-east1/clusters/prod/nodePools/pool-1",
            "instance_id": INSTANCE["partial_uri"],
        }]

    def test_empty_instances_produce_no_rows(self):
        assert compute._build_instance_tag_rows([]) == []
        assert compute._build_nic_rows([]) == []
        assert compute._build_access_config_rows([]) == []
        assert compute._build_service_account_rows([]) == []
        assert compute._build_gke_cluster_link_rows([]) == []
        assert compute._build_gke_node_pool_link_rows([]) == []


class TestLoadGcpInstancesBatching:
    def test_attachments_are_batched_not_per_item(self):
        session = MagicMock()
        instances = [INSTANCE, {**INSTANCE, "partial_uri": "projects/p1/zones/z1/instances/vm-2"}]

        compute.load_gcp_instances(session, instances, TEST_UPDATE_TAG)

        # 1 instance batch + tags + nics + access configs + vpc membership +
        # service accounts + gke cluster links + gke pool links + image relations
        # = 9 writes total for ANY number of instances (was ~8 writes PER instance).
        assert session.execute_write.call_count == 9
        unwind_calls = [c for c in session.execute_write.call_args_list if "DictList" in c.kwargs]
        for call in unwind_calls:
            assert "UNWIND" in call.args[1]

    def test_no_gke_instances_skips_gke_writes(self):
        session = MagicMock()
        plain = {**INSTANCE, "gke_cluster_name": None, "gke_node_pool_name": None}

        compute.load_gcp_instances(session, [plain], TEST_UPDATE_TAG)

        queries = [c.args[1] for c in session.execute_write.call_args_list if len(c.args) > 1]
        assert not any("GKECluster" in q for q in queries)
        assert not any("GKENodePool" in q for q in queries)


FIREWALL = {
    "id": "projects/p1/global/firewalls/allow-web",
    "direction": "INGRESS",
    "disabled": False,
    "name": "allow-web",
    "priority": 1000,
    "selfLink": "https://selflink/fw",
    "vpc_partial_uri": "projects/p1/global/networks/default",
    "has_target_service_accounts": False,
    "consolelink": "https://console/fw",
    "network": "https://net/default",
    "sourceRanges": ["34.1.2.3/32", "10.0.0.0/8", "2001:db8::/32"],
    "transformed_allow_list": [
        {"ruleid": "fw/allow/tcp/80", "protocol": "tcp", "fromport": 80, "toport": 80},
    ],
    "transformed_deny_list": [
        {"ruleid": "fw/deny/tcp/22", "protocol": "tcp", "fromport": 22, "toport": 22},
    ],
    "targetTags": ["web"],
}


class TestFirewallRowBuilders:
    def test_rule_rows_partitioned_by_label_and_ip_type(self):
        partitions = compute._build_firewall_rule_rows([FIREWALL])

        # 1 allow rule x 3 ranges (2 v4 + 1 v6); same for deny
        assert len(partitions[("ALLOWED_BY", "IPv4")]) == 2
        assert len(partitions[("ALLOWED_BY", "IPv6")]) == 1
        assert len(partitions[("DENIED_BY", "IPv4")]) == 2
        assert len(partitions[("DENIED_BY", "IPv6")]) == 1
        row = partitions[("ALLOWED_BY", "IPv4")][0]
        assert row == {
            "fw_id": FIREWALL["id"],
            "ruleid": "fw/allow/tcp/80",
            "protocol": "tcp",
            "fromport": 80,
            "toport": 80,
            "range": "34.1.2.3/32",
        }

    def test_target_tag_rows(self):
        rows = compute._build_target_tag_rows([FIREWALL])
        assert rows == [{
            "fw_id": FIREWALL["id"],
            "tag_id": "projects/p1/global/networks/default/tags/web",
            "tag_value": "web",
        }]

    def test_public_ip_rows_exclude_private_ranges(self):
        rows = compute._build_firewall_public_ip_rows([FIREWALL])
        # 10.0.0.0/8 is private; 2001:db8::/32 fails IPv4Network parsing and is skipped
        assert rows == [{"fw_id": FIREWALL["id"], "ip": "34.1.2.3/32"}]


class TestLoadGcpIngressFirewalls:
    def test_batched_writes(self):
        session = MagicMock()

        compute.load_gcp_ingress_firewalls(session, [FIREWALL, FIREWALL], TEST_UPDATE_TAG)

        # 1 firewall batch + 4 rule partitions + 1 target tags + 1 public ips = 7
        # (independent of firewall count; was ~7+ writes PER firewall)
        assert session.execute_write.call_count == 7
        queries = [c.args[1] for c in session.execute_write.call_args_list]
        assert sum("ALLOWED_BY" in q for q in queries) == 2  # v4 + v6 partitions
        assert sum("DENIED_BY" in q for q in queries) == 2
        assert sum("Ipv6Range" in q for q in queries) == 2
        assert all("UNWIND $DictList" in q for q in queries)

    def test_empty_list_writes_nothing(self):
        session = MagicMock()
        compute.load_gcp_ingress_firewalls(session, [], TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()


class TestAttachComputeDisksToInstances:
    def test_single_batched_write(self):
        session = MagicMock()
        rows = [
            {"id": "projects/p1/disks/d1", "instance_id": "projects/p1/zones/z1/instances/vm-1"},
            {"id": "projects/p1/disks/d2", "instance_id": "projects/p1/zones/z1/instances/vm-2"},
        ]

        compute.attach_compute_disks_to_instances(session, rows, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert call.kwargs["DictList"] == rows
        assert "record.instance_id" in call.args[1]

    def test_empty_rows_write_nothing(self):
        session = MagicMock()
        compute.attach_compute_disks_to_instances(session, [], TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()
