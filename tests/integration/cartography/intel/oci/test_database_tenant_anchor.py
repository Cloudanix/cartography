"""
Database lookups reach existing nodes only through the syncing tenancy (AGENTS.md "Tenant isolation").
Tenancy B already holds the subnet / NSG / KMS key / DB system / DB node an id in tenancy A's API data
points at; A's sync must not link to it.
"""
import pytest

from cartography.intel.oci import database
from cartography.intel.oci import network
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
TAG = 7


def _tenancy_with_dependencies(neo4j_session, prefix):
    ids = seed_tenancy(neo4j_session, prefix)
    tenancy, compartment = ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID']
    args = (tenancy, compartment, REGION, TAG)
    network.load_vcns(neo4j_session, [{'id': f'{prefix}-vcn', 'compartment-id': compartment}], *args)
    network.load_subnets(neo4j_session, [{'id': f'{prefix}-subnet', 'vcn-id': f'{prefix}-vcn'}], *args)
    network.load_network_security_groups(neo4j_session, [{'id': f'{prefix}-nsg', 'vcn-id': f'{prefix}-vcn'}], *args)
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment})
        MERGE (c)-[:RESOURCE]->(v:OCIKmsVault{id: $prefix + '-vault'})
        MERGE (v)-[:OCI_KMS_KEY]->(:OCIKmsKey{id: $prefix + '-key'})
        """,
        compartment=compartment, prefix=prefix,
    )
    database.load_db_systems(neo4j_session, [{'id': f'{prefix}-sys'}], tenancy, compartment, TAG)
    database.load_db_nodes(
        neo4j_session, [{'id': f'{prefix}-node', 'db_system_id': f'{prefix}-sys', 'vnic_id': 'shared-vnic'}],
        tenancy, TAG,
    )
    return ids


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    return _tenancy_with_dependencies(neo4j_session, 'db-a'), _tenancy_with_dependencies(neo4j_session, 'db-b')


def _db(db_id, ref):
    return {
        'id': db_id, 'subnet_id': f'{ref}-subnet', 'nsg_ids': [f'{ref}-nsg'], 'kms_key_id': f'{ref}-key',
    }


@pytest.mark.parametrize('loader', [database.load_autonomous_databases, database.load_db_systems])
def test_db_resources_link_only_inside_the_syncing_tenancy(neo4j_session, tenants, loader):
    a, b = tenants
    loader(
        neo4j_session, [_db('a-own', 'db-a'), _db('a-foreign', 'db-b')],
        a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], TAG,
    )
    for rel, target in (('OCI_SUBNET', 'subnet'), ('OCI_NSG', 'nsg'), ('OCI_KMS_KEY', 'key')):
        assert linked(neo4j_session, 'a-own', rel, f'db-a-{target}'), rel
        assert not linked(neo4j_session, 'a-foreign', rel, f'db-b-{target}'), rel

    # A compartment that is not in the syncing tenancy (a mismatched job parameter) finds nothing.
    loader(neo4j_session, [{'id': 'a-misplaced'}], a['OCI_TENANCY_ID'], b['OCI_COMPARTMENT_ID'], TAG)
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-own')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-misplaced')


def test_db_homes_and_nodes_attach_only_to_the_syncing_tenancys_db_system(neo4j_session, tenants):
    a, _ = tenants
    homes = [
        {'id': 'a-home', 'db_system_id': 'db-a-sys', 'kms_key_id': 'db-a-key'},
        {'id': 'a-home-foreign', 'db_system_id': 'db-b-sys', 'kms_key_id': 'db-b-key'},
    ]
    database.load_db_homes(neo4j_session, homes, a['OCI_TENANCY_ID'], TAG)
    nodes = [{'id': 'a-node-2', 'db_system_id': 'db-a-sys'}, {'id': 'a-node-foreign', 'db_system_id': 'db-b-sys'}]
    database.load_db_nodes(neo4j_session, nodes, a['OCI_TENANCY_ID'], TAG)

    assert linked(neo4j_session, 'db-a-sys', 'HAS_DB_HOME', 'a-home')
    assert linked(neo4j_session, 'a-home', 'OCI_KMS_KEY', 'db-a-key')
    assert linked(neo4j_session, 'db-a-sys', 'HAS_DB_NODE', 'a-node-2')
    assert not linked(neo4j_session, 'db-b-sys', 'HAS_DB_HOME', 'a-home-foreign')
    assert not linked(neo4j_session, 'a-home-foreign', 'OCI_KMS_KEY', 'db-b-key')
    assert not linked(neo4j_session, 'db-b-sys', 'HAS_DB_NODE', 'a-node-foreign')


def test_db_node_vnic_links_only_the_syncing_tenancys_db_node(neo4j_session, tenants):
    a, _ = tenants
    # Both tenancies hold a DB node whose vnic_id names the VNIC; only A's sync is loading it.
    database.load_db_node_vnics(
        neo4j_session, [{'id': 'shared-vnic', 'subnet-id': 'db-b-subnet'}], a['OCI_TENANCY_ID'], REGION, TAG,
    )
    assert linked(neo4j_session, 'db-a-node', 'OCI_VNIC', 'shared-vnic')
    assert not linked(neo4j_session, 'db-b-node', 'OCI_VNIC', 'shared-vnic')
    assert not linked(neo4j_session, 'db-b-subnet', 'OCI_VNIC', 'shared-vnic')
