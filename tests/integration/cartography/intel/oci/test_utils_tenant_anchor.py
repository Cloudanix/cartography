"""utils tenancy readers return only the given tenancy's nodes (AGENTS.md "Tenant isolation")."""
from cartography.intel.oci import utils
from tests.integration.cartography.intel.oci.common import seed_tenancy


def test_security_groups_in_tenancy_are_read_from_the_tenancy_only(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    a, b = seed_tenancy(neo4j_session, 'utl-a'), seed_tenancy(neo4j_session, 'utl-b')
    for prefix, ids in (('utl-a', a), ('utl-b', b)):
        neo4j_session.run(
            """
            MATCH (c:OCICompartment{id: $compartment})
            MERGE (r:OCIRegion{name: 'us-phoenix-1'})
            MERGE (c)-[:RESOURCE]->(:OCIVcn{id: $prefix + '-vcn'})
                -[:OCI_NETWORK_SECURITY_GROUP]->(g:OCINetworkSecurityGroup{id: $prefix + '-nsg'})
            SET g.ocid = g.id
            MERGE (g)-[:OCI_REGION]->(r)
            """,
            compartment=ids['OCI_COMPARTMENT_ID'], prefix=prefix,
        )
    # A cross-tenant edge left from before anchoring (any type) must not lead the read into tenancy B.
    neo4j_session.run("MATCH (a:OCIVcn{id: 'utl-a-vcn'}), (b:OCIVcn{id: 'utl-b-vcn'}) MERGE (a)-[:STALE_LINK]->(b)")
    rows = utils.get_security_groups_in_tenancy(neo4j_session, a['OCI_TENANCY_ID'], 'us-phoenix-1')
    assert [row['ocid'] for row in rows] == ['utl-a-nsg']
