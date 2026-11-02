"""
OKE lookups reach existing nodes only through the syncing tenancy (AGENTS.md "Tenant isolation").
"""
import pytest

from cartography.intel.oci import oke
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

TAG = 7


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    a, b = seed_tenancy(neo4j_session, 'oke-a'), seed_tenancy(neo4j_session, 'oke-b')
    for prefix, ids in (('oke-a', a), ('oke-b', b)):
        oke.load_clusters(
            neo4j_session, [{'id': f'{prefix}-cl'}], ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID'], TAG,
        )
        neo4j_session.run(
            "MATCH (c:OCICompartment{id: $c}) MERGE (c)-[:RESOURCE]->(:OCIInstance{id: $i})",
            c=ids['OCI_COMPARTMENT_ID'], i=f'{prefix}-inst',
        )
    return a, b


def test_clusters_and_pools_attach_only_inside_the_syncing_tenancy(neo4j_session, tenants):
    a, b = tenants
    # A compartment that is not in the syncing tenancy (a mismatched job parameter) finds nothing.
    oke.load_clusters(neo4j_session, [{'id': 'a-cl-misplaced'}], a['OCI_TENANCY_ID'], b['OCI_COMPARTMENT_ID'], TAG)
    pools = [{'id': 'a-pool', 'cluster_id': 'oke-a-cl'}, {'id': 'a-pool-foreign', 'cluster_id': 'oke-b-cl'}]
    oke.load_node_pools(neo4j_session, pools, a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], TAG)
    oke.load_node_pools(
        neo4j_session, [{'id': 'a-pool-misplaced'}], a['OCI_TENANCY_ID'], b['OCI_COMPARTMENT_ID'], TAG,
    )
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'oke-a-cl')
    assert linked(neo4j_session, 'oke-a-cl', 'HAS_NODE_POOL', 'a-pool')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-cl-misplaced')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-pool-misplaced')
    assert not linked(neo4j_session, 'oke-b-cl', 'HAS_NODE_POOL', 'a-pool-foreign')


def test_node_links_reach_only_the_syncing_tenancys_instances(neo4j_session, tenants):
    a, _ = tenants
    # Tenancy A's pool lists a worker OCID that tenancy B holds.
    pools = [{'id': 'a-pool', 'cluster_id': 'oke-a-cl', 'nodes': [{'ocid': 'oke-a-inst'}, {'ocid': 'oke-b-inst'}]}]
    oke.load_node_pools(neo4j_session, pools, a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], TAG)
    oke.link_oke_nodes(neo4j_session, {**a, 'UPDATE_TAG': TAG})
    assert linked(neo4j_session, 'a-pool', 'HAS_NODE', 'oke-a-inst')
    assert linked(neo4j_session, 'oke-a-cl', 'HAS_NODE', 'oke-a-inst')
    assert not linked(neo4j_session, 'a-pool', 'HAS_NODE', 'oke-b-inst')
    assert not linked(neo4j_session, 'oke-a-cl', 'HAS_NODE', 'oke-b-inst')
