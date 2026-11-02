"""
The OCI exposure analysis jobs read subnets, security lists, NSGs, route tables and internet gateways
only from the tenancy they run for (AGENTS.md "Tenant isolation"). Tenancy B holds an open subnet / NSG
/ route that tenancy A's resources name by id; A's evaluation must treat them as unresolved, never as
B's rules.
"""
import pytest

from cartography.intel.oci import network
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
TAG = 7
OPEN_SSH = {'protocol': '6', 'source': '0.0.0.0/0', 'tcp-options': {'destination-port-range': {'min': 22, 'max': 22}}}
OPEN_ALL = {'protocol': 'all', 'source': '0.0.0.0/0'}


def _network(neo4j_session, prefix, ids):
    """VCN with an open security list, an open NSG, an IGW and a subnet routed to it."""
    args = (ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID'], REGION, TAG)
    vcn, igw = f'{prefix}-vcn', f'ocid1.internetgateway.oc1..{prefix}'
    network.load_vcns(neo4j_session, [{'id': vcn, 'compartment-id': ids['OCI_COMPARTMENT_ID']}], *args)
    network.load_security_lists(
        neo4j_session, [{'id': f'{prefix}-sl', 'vcn-id': vcn, 'ingress-security-rules': [OPEN_ALL]}], *args,
    )
    network.load_network_security_groups(neo4j_session, [{'id': f'{prefix}-nsg', 'vcn-id': vcn}], *args)
    network.load_nsg_security_rules(
        neo4j_session, [{'id': 'r', 'direction': 'INGRESS', **OPEN_ALL}], f'{prefix}-nsg', ids['OCI_TENANCY_ID'], TAG,
    )
    network.load_internet_gateways(neo4j_session, [{'id': igw, 'vcn-id': vcn, 'is-enabled': True}], *args)
    network.load_route_tables(
        neo4j_session,
        [{
            'id': f'{prefix}-rt', 'vcn-id': vcn,
            'route-rules': [{'destination': '0.0.0.0/0', 'network-entity-id': igw}],
        }],
        *args,
    )
    network.load_subnets(
        neo4j_session,
        [{
            'id': f'{prefix}-subnet', 'vcn-id': vcn,
            'security-list-ids': [f'{prefix}-sl'], 'route-table-id': f'{prefix}-rt',
        }],
        *args,
    )


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    a, b = seed_tenancy(neo4j_session, 'xj-a'), seed_tenancy(neo4j_session, 'xj-b')
    _network(neo4j_session, 'xj-a', a)
    _network(neo4j_session, 'xj-b', b)
    return {**a, 'UPDATE_TAG': TAG}


def _seed(neo4j_session, params, query, **kwargs):
    neo4j_session.run(
        "MATCH (c:OCICompartment{id: $compartment}) " + query, compartment=params['OCI_COMPARTMENT_ID'], **kwargs,
    )


def _types(neo4j_session, node_id):
    row = neo4j_session.run("MATCH (n{id: $id}) RETURN n.exposed_internet_type AS t", id=node_id).single()
    return sorted(row['t'] or [])


def _instance(neo4j_session, params, instance_id, prefix):
    _seed(
        neo4j_session, params,
        """
        MERGE (c)-[:RESOURCE]->(i:OCIInstance{id: $id})
        MERGE (i)-[:OCI_VNIC_ATTACHMENT]->(:OCIVnicAttachment{id: $id + '-att'})
            -[:OCI_VNIC]->(v:OCIVnic{id: $id + '-vnic'})
        SET v.public_ip = '203.0.113.5', v.subnet_id = $prefix + '-subnet', v.nsg_ids = [$prefix + '-nsg']
        """,
        id=instance_id, prefix=prefix,
    )


def test_instance_exposure_reads_only_the_tenancys_subnet_and_nsg(neo4j_session, tenants):
    _instance(neo4j_session, tenants, 'xj-inst-own', 'xj-a')
    _instance(neo4j_session, tenants, 'xj-inst-foreign', 'xj-b')
    run_analysis_job('oci_instance_asset_exposure.json', neo4j_session, tenants)
    assert _types(neo4j_session, 'xj-inst-own') == ['unrestricted_nsg_ingress', 'unrestricted_securitylist_ingress']
    assert _types(neo4j_session, 'xj-inst-foreign') == ['public_ip_unresolved_rules']


def test_db_node_exposure_reads_only_the_tenancys_subnet_and_nsg(neo4j_session, tenants):
    for node_id, prefix in (('xj-dbn-own', 'xj-a'), ('xj-dbn-foreign', 'xj-b')):
        _seed(
            neo4j_session, tenants,
            """
            MERGE (c)-[:RESOURCE]->(s:OCIDbSystem{id: $id + '-sys'})
            MERGE (s)-[:HAS_DB_NODE]->(dn:OCIDbNode{id: $id})
            MERGE (dn)-[:OCI_VNIC]->(v:OCIVnic{id: $id + '-vnic'})
            SET dn.vnic_id = $id + '-vnic', v.public_ip = '203.0.113.6',
                v.subnet_id = $prefix + '-subnet', v.nsg_ids = [$prefix + '-nsg']
            """,
            id=node_id, prefix=prefix,
        )
    run_analysis_job('oci_db_system_asset_exposure.json', neo4j_session, tenants)
    assert _types(neo4j_session, 'xj-dbn-own') == ['unrestricted_nsg_ingress', 'unrestricted_securitylist_ingress']
    assert _types(neo4j_session, 'xj-dbn-foreign') == ['public_ip_unresolved_rules']


def test_load_balancer_exposure_reads_only_the_tenancys_subnet_and_nsg(neo4j_session, tenants):
    for lb_id, prefix in (('xj-lb-own', 'xj-a'), ('xj-lb-foreign', 'xj-b')):
        _seed(
            neo4j_session, tenants,
            "MERGE (c)-[:RESOURCE]->(lb:OCILoadBalancer{id: $id}) "
            "SET lb.is_private = false, lb.listener_targets = ['6:22'], "
            "lb.subnet_ids = [$prefix + '-subnet'], lb.nsg_ids = [$prefix + '-nsg']",
            id=lb_id, prefix=prefix,
        )
    run_analysis_job('oci_load_balancer_asset_exposure.json', neo4j_session, tenants)
    assert _types(neo4j_session, 'xj-lb-own') == ['unrestricted_nsg_ingress', 'unrestricted_securitylist_ingress']
    assert _types(neo4j_session, 'xj-lb-foreign') == ['public_lb_unresolved_rules']


def test_api_gateway_exposure_reads_only_the_tenancys_subnet_and_nsg(neo4j_session, tenants):
    for gw_id, prefix in (('xj-gw-own', 'xj-a'), ('xj-gw-foreign', 'xj-b')):
        _seed(
            neo4j_session, tenants,
            "MERGE (c)-[:RESOURCE]->(gw:OCIApiGateway{id: $id}) "
            "SET gw.endpoint_type = 'PUBLIC', gw.subnet_id = $prefix + '-subnet', gw.nsg_ids = [$prefix + '-nsg']",
            id=gw_id, prefix=prefix,
        )
    run_analysis_job('oci_api_gateway_asset_exposure.json', neo4j_session, tenants)
    assert _types(neo4j_session, 'xj-gw-own') == ['unrestricted_nsg_ingress', 'unrestricted_securitylist_ingress']
    assert _types(neo4j_session, 'xj-gw-foreign') == ['public_gateway_unresolved_rules']


def test_oke_endpoint_exposure_reads_only_the_tenancys_subnet_and_nsg(neo4j_session, tenants):
    for cluster_id, prefix in (('xj-oke-own', 'xj-a'), ('xj-oke-foreign', 'xj-b')):
        _seed(
            neo4j_session, tenants,
            "MERGE (c)-[:RESOURCE]->(cl:OCIOKECluster{id: $id}) "
            "SET cl.endpoint_is_public_ip_enabled = true, cl.endpoint_subnet_id = $prefix + '-subnet', "
            "cl.endpoint_nsg_ids = [$prefix + '-nsg']",
            id=cluster_id, prefix=prefix,
        )
    run_analysis_job('oci_oke_cluster_asset_exposure.json', neo4j_session, tenants)
    assert _types(neo4j_session, 'xj-oke-own') == ['unrestricted_nsg_ingress', 'unrestricted_securitylist_ingress']
    assert _types(neo4j_session, 'xj-oke-foreign') == ['public_endpoint_unresolved_rules']


def test_subnet_exposure_reads_only_the_tenancys_route_table_and_gateway(neo4j_session, tenants):
    # Tenancy A's second subnet names tenancy B's route table (which routes to B's gateway).
    network.load_subnets(
        neo4j_session, [{'id': 'xj-a-subnet-2', 'vcn-id': 'xj-a-vcn', 'route-table-id': 'xj-b-rt'}],
        tenants['OCI_TENANCY_ID'], tenants['OCI_COMPARTMENT_ID'], REGION, TAG,
    )
    run_analysis_job('oci_subnet_asset_exposure.json', neo4j_session, tenants)
    assert _types(neo4j_session, 'xj-a-subnet') == ['internet_gateway_route']
    assert _types(neo4j_session, 'xj-a-subnet-2') == ['public_subnet_unresolved_route_table']
