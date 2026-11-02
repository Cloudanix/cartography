"""
Network lookups reach existing nodes only through the syncing tenancy (AGENTS.md "Tenant isolation").
Tenancy B already holds the node an id in tenancy A's API data points at; A's sync must not link to it.
"""
from unittest.mock import MagicMock

import pytest

from cartography.intel.oci import api_gateway
from cartography.intel.oci import load_balancer
from cartography.intel.oci import network
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
TAG = 7


def _tenancy_with_vcn(neo4j_session, prefix):
    ids = seed_tenancy(neo4j_session, prefix)
    tenancy, compartment = ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID']
    vcn = f'{prefix}-vcn'
    args = (tenancy, compartment, REGION, TAG)
    network.load_vcns(neo4j_session, [{'id': vcn, 'compartment-id': compartment}], *args)
    network.load_subnets(
        neo4j_session,
        [{'id': f'{prefix}-subnet', 'vcn-id': vcn, 'route-table-id': f'{prefix}-rt', 'security-list-ids': []}],
        *args,
    )
    network.load_route_tables(neo4j_session, [{'id': f'{prefix}-rt', 'vcn-id': vcn}], *args)
    network.load_security_lists(neo4j_session, [{'id': f'{prefix}-sl', 'vcn-id': vcn}], *args)
    network.load_network_security_groups(neo4j_session, [{'id': f'{prefix}-nsg', 'vcn-id': vcn}], *args)
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment})
        MERGE (c)-[:RESOURCE]->(i:OCIInstance{id: $prefix + '-instance'})
        MERGE (i)-[:OCI_VNIC_ATTACHMENT]->(:OCIVnicAttachment{id: $prefix + '-att', vnic_id: 'shared-vnic'})
        """,
        compartment=compartment, prefix=prefix,
    )
    return ids


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    return _tenancy_with_vcn(neo4j_session, 'net-a'), _tenancy_with_vcn(neo4j_session, 'net-b')


def test_vcn_attaches_only_to_a_compartment_of_the_syncing_tenancy(neo4j_session, tenants):
    a, b = tenants
    network.load_vcns(
        neo4j_session, [{'id': 'a-vcn-2', 'compartment-id': b['OCI_COMPARTMENT_ID']}],
        a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG,
    )
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-vcn-2')
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'net-a-vcn')


@pytest.mark.parametrize(
    'loader, rel', [
        (network.load_subnets, 'OCI_SUBNET'),
        (network.load_security_lists, 'OCI_SECURITY_LIST'),
        (network.load_network_security_groups, 'OCI_NETWORK_SECURITY_GROUP'),
        (network.load_internet_gateways, 'OCI_INTERNET_GATEWAY'),
        (network.load_nat_gateways, 'OCI_NAT_GATEWAY'),
        (network.load_route_tables, 'OCI_ROUTE_TABLE'),
    ],
)
def test_vcn_children_link_only_to_a_vcn_of_the_syncing_tenancy(neo4j_session, tenants, loader, rel):
    a, _ = tenants
    loader(
        neo4j_session, [{'id': 'a-own', 'vcn-id': 'net-a-vcn'}, {'id': 'a-foreign', 'vcn-id': 'net-b-vcn'}],
        a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG,
    )
    assert linked(neo4j_session, 'net-a-vcn', rel, 'a-own')
    assert not linked(neo4j_session, 'net-b-vcn', rel, 'a-foreign')


def test_nsg_rules_link_only_to_an_nsg_of_the_syncing_tenancy(neo4j_session, tenants):
    a, _ = tenants
    rule = [{'id': 'R1', 'direction': 'INGRESS'}]
    network.load_nsg_security_rules(neo4j_session, rule, 'net-a-nsg', a['OCI_TENANCY_ID'], TAG)
    network.load_nsg_security_rules(neo4j_session, rule, 'net-b-nsg', a['OCI_TENANCY_ID'], TAG)
    assert linked(neo4j_session, 'net-a-nsg', 'OCI_NSG_RULE', 'net-a-nsg/R1')
    assert not linked(neo4j_session, 'net-b-nsg', 'OCI_NSG_RULE', 'net-b-nsg/R1')


def test_subnet_associations_stay_in_the_syncing_tenancy(neo4j_session, tenants):
    a, _ = tenants
    # Tenancy A's subnet names B's route table and security list (ids from A's API data).
    neo4j_session.run(
        "MATCH (s:OCISubnet{id: 'net-a-subnet'}) "
        "SET s.region = $region, s.ocid = s.id, s.security_list_ids = ['net-a-sl', 'net-b-sl']",
        region=REGION,
    )
    network.sync_subnet_associations(
        neo4j_session, MagicMock(), [{'ocid': a['OCI_COMPARTMENT_ID']}], a['OCI_TENANCY_ID'], REGION, TAG, a,
    )
    assert linked(neo4j_session, 'net-a-subnet', 'OCI_ROUTE_TABLE', 'net-a-rt')
    assert linked(neo4j_session, 'net-a-subnet', 'OCI_SECURITY_LIST', 'net-a-sl')
    assert not linked(neo4j_session, 'net-a-subnet', 'OCI_SECURITY_LIST', 'net-b-sl')

    neo4j_session.run("MATCH (s:OCISubnet{id: 'net-a-subnet'}) SET s.route_table_id = 'net-b-rt'")
    network.sync_subnet_associations(
        neo4j_session, MagicMock(), [{'ocid': a['OCI_COMPARTMENT_ID']}], a['OCI_TENANCY_ID'], REGION, TAG, a,
    )
    assert not linked(neo4j_session, 'net-a-subnet', 'OCI_ROUTE_TABLE', 'net-b-rt')


def test_vnic_links_only_to_the_syncing_tenancys_subnet_and_attachment(neo4j_session, tenants):
    a, _ = tenants
    # Both tenancies hold an attachment naming the VNIC; A's VNIC names B's subnet.
    network.load_vnics(
        neo4j_session,
        [{'id': 'shared-vnic', 'subnet-id': 'net-b-subnet'}, {'id': 'a-vnic', 'subnet-id': 'net-a-subnet'}],
        a['OCI_TENANCY_ID'], REGION, TAG,
    )
    assert linked(neo4j_session, 'net-a-att', 'OCI_VNIC', 'shared-vnic')
    assert not linked(neo4j_session, 'net-b-att', 'OCI_VNIC', 'shared-vnic')
    assert linked(neo4j_session, 'net-a-subnet', 'OCI_VNIC', 'a-vnic')
    assert not linked(neo4j_session, 'net-b-subnet', 'OCI_VNIC', 'shared-vnic')


def test_flow_logs_link_only_to_the_syncing_tenancys_subnet_or_vcn(neo4j_session, tenants):
    a, _ = tenants

    def flow_log(log_id, resource):
        return {'id': log_id, 'configuration': {'source': {'service': 'flowlogs', 'resource': resource}}}

    network.load_flow_logs(
        neo4j_session,
        [
            flow_log('a-subnet-log', 'net-a-subnet'), flow_log('a-vcn-log', 'net-a-vcn'),
            flow_log('b-subnet-log', 'net-b-subnet'), flow_log('b-vcn-log', 'net-b-vcn'),
        ],
        'lg', a['OCI_TENANCY_ID'], REGION, TAG,
    )
    assert linked(neo4j_session, 'net-a-subnet', 'OCI_FLOW_LOG', 'a-subnet-log')
    assert linked(neo4j_session, 'net-a-vcn', 'OCI_FLOW_LOG', 'a-vcn-log')
    assert not linked(neo4j_session, 'net-b-subnet', 'OCI_FLOW_LOG', 'b-subnet-log')
    assert not linked(neo4j_session, 'net-b-vcn', 'OCI_FLOW_LOG', 'b-vcn-log')


def test_load_balancer_and_gateway_attach_only_to_the_syncing_tenancys_compartment(neo4j_session, tenants):
    a, b = tenants
    # A compartment id that is not in the syncing tenancy (a mismatched job parameter) finds nothing.
    for tenancy, compartment, suffix in (
        (a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], 'own'),
        (a['OCI_TENANCY_ID'], b['OCI_COMPARTMENT_ID'], 'foreign'),
    ):
        load_balancer.load_load_balancers(
            neo4j_session, [{'id': f'lb-{suffix}'}], load_balancer.LOAD_BALANCER_LABEL, tenancy, compartment, TAG,
        )
        api_gateway.load_gateways(neo4j_session, [{'id': f'gw-{suffix}'}], tenancy, compartment, TAG)
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'lb-own')
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'gw-own')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'lb-foreign')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'gw-foreign')
