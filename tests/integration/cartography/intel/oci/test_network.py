# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.network as test_data
from cartography.intel.oci import network
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_COMPARTMENT_ID = test_data.TEST_COMPARTMENT_ID
TEST_TENANCY_ID = test_data.TEST_TENANCY_ID
TEST_REGION = test_data.TEST_REGION
TEST_UPDATE_TAG = 123456789


def _seed_compartment(neo4j_session):
    neo4j_session.run(
        "MERGE (c:OCICompartment{id: $id}) SET c.lastupdated = $tag",
        id=TEST_COMPARTMENT_ID,
        tag=TEST_UPDATE_TAG,
    )


def _seed_vcn(neo4j_session):
    _seed_compartment(neo4j_session)
    network.load_vcns(
        neo4j_session, test_data.VCNS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )


def test_load_vcns(neo4j_session):
    _seed_compartment(neo4j_session)
    network.load_vcns(
        neo4j_session, test_data.VCNS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIVcn", ["id"]) == {(test_data.VCN_ID,)}
    assert (TEST_COMPARTMENT_ID, test_data.VCN_ID) in check_rels(
        neo4j_session, "OCICompartment", "id", "OCIVcn", "id", "RESOURCE",
    )


def test_load_subnets(neo4j_session):
    _seed_vcn(neo4j_session)
    network.load_subnets(
        neo4j_session, test_data.SUBNETS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCISubnet", ["id"]) == {(test_data.SUBNET_ID,)}
    assert (test_data.VCN_ID, test_data.SUBNET_ID) in check_rels(
        neo4j_session, "OCIVcn", "id", "OCISubnet", "id", "OCI_SUBNET",
    )


def test_load_security_lists(neo4j_session):
    _seed_vcn(neo4j_session)
    network.load_security_lists(
        neo4j_session, test_data.SECURITY_LISTS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCISecurityList", ["id"]) == {("oci.sl.0",)}
    assert (test_data.VCN_ID, "oci.sl.0") in check_rels(
        neo4j_session, "OCIVcn", "id", "OCISecurityList", "id", "OCI_SECURITY_LIST",
    )


def test_load_nsgs_and_rules(neo4j_session):
    _seed_vcn(neo4j_session)
    network.load_network_security_groups(
        neo4j_session, test_data.NETWORK_SECURITY_GROUPS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert (test_data.VCN_ID, test_data.NSG_ID) in check_rels(
        neo4j_session, "OCIVcn", "id", "OCINetworkSecurityGroup", "id",
        "OCI_NETWORK_SECURITY_GROUP",
    )
    network.load_nsg_security_rules(
        neo4j_session, test_data.NSG_SECURITY_RULES, test_data.NSG_ID, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCINsgSecurityRule", ["id", "tcp_dest_port_min"]) == {
        ("oci.nsgrule.0", 22),
    }
    assert (test_data.NSG_ID, "oci.nsgrule.0") in check_rels(
        neo4j_session, "OCINetworkSecurityGroup", "id", "OCINsgSecurityRule", "id",
        "OCI_NSG_RULE",
    )


def test_load_internet_gateways(neo4j_session):
    _seed_vcn(neo4j_session)
    network.load_internet_gateways(
        neo4j_session, test_data.INTERNET_GATEWAYS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert (test_data.VCN_ID, "oci.igw.0") in check_rels(
        neo4j_session, "OCIVcn", "id", "OCIInternetGateway", "id", "OCI_INTERNET_GATEWAY",
    )


def test_load_nat_gateways(neo4j_session):
    _seed_vcn(neo4j_session)
    network.load_nat_gateways(
        neo4j_session, test_data.NAT_GATEWAYS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert (test_data.VCN_ID, "oci.nat.0") in check_rels(
        neo4j_session, "OCIVcn", "id", "OCINatGateway", "id", "OCI_NAT_GATEWAY",
    )


def test_load_route_tables(neo4j_session):
    _seed_vcn(neo4j_session)
    network.load_route_tables(
        neo4j_session, test_data.ROUTE_TABLES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert (test_data.VCN_ID, "oci.rt.0") in check_rels(
        neo4j_session, "OCIVcn", "id", "OCIRouteTable", "id", "OCI_ROUTE_TABLE",
    )


def test_load_vnics_links_subnet(neo4j_session):
    _seed_vcn(neo4j_session)
    network.load_subnets(
        neo4j_session, test_data.SUBNETS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    network.load_vnics(neo4j_session, test_data.VNICS, TEST_REGION, TEST_UPDATE_TAG)
    assert check_nodes(neo4j_session, "OCIVnic", ["id"]) == {("oci.vnic.0",)}
    assert (test_data.SUBNET_ID, "oci.vnic.0") in check_rels(
        neo4j_session, "OCISubnet", "id", "OCIVnic", "id", "OCI_VNIC",
    )


def test_load_flow_logs_links_subnet(neo4j_session):
    _seed_vcn(neo4j_session)
    network.load_subnets(
        neo4j_session, test_data.SUBNETS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    network.load_flow_logs(
        neo4j_session, test_data.FLOW_LOGS, "oci.lg.0", TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIFlowLog", ["id"]) == {("oci.flowlog.0",)}
    assert (test_data.SUBNET_ID, "oci.flowlog.0") in check_rels(
        neo4j_session, "OCISubnet", "id", "OCIFlowLog", "id", "OCI_FLOW_LOG",
    )
