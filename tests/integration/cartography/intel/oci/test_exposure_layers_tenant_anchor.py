"""
Exposure-layer reads resolve ids only inside the syncing tenancy (AGENTS.md "Tenant isolation"): a
route table or image id that tenancy B holds is unknown to tenancy A's evaluation.
"""
from cartography.intel.oci.exposure_layers import network as exposure_network
from cartography.intel.oci.exposure_layers import software
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
IGW_ROUTE = [{'destination': '0.0.0.0/0', 'networkEntityId': 'igw'}]


def _seed(neo4j_session, prefix, ids):
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment})
        MERGE (c)-[:RESOURCE]->(v:OCIVcn{id: $prefix + '-vcn'})
        MERGE (v)-[:OCI_ROUTE_TABLE]->(:OCIRouteTable{id: $prefix + '-rt', route_rules: $rules})
        MERGE (c)-[:RESOURCE]->(:OCIImage{id: $prefix + '-image', display_name: 'Oracle-Linux-8.9-2024.01.26-0'})
        """,
        compartment=ids['OCI_COMPARTMENT_ID'], prefix=prefix, rules=str(IGW_ROUTE),
    )


def test_subnet_route_table_and_instance_image_resolve_only_inside_the_syncing_tenancy(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    a, b = seed_tenancy(neo4j_session, 'xla-a'), seed_tenancy(neo4j_session, 'xla-b')
    _seed(neo4j_session, 'xla-a', a)
    _seed(neo4j_session, 'xla-b', b)
    # Tenancy A's subnets and instances name tenancy B's route table and image.
    neo4j_session.run(
        """
        MATCH (c:OCICompartment{id: $compartment})-[:RESOURCE]->(v:OCIVcn{id: 'xla-a-vcn'})
        MERGE (v)-[:OCI_SUBNET]->(:OCISubnet{id: 'a-own', route_table_id: 'xla-a-rt'})
        MERGE (v)-[:OCI_SUBNET]->(:OCISubnet{id: 'a-foreign', route_table_id: 'xla-b-rt'})
        MERGE (c)-[:RESOURCE]->(:OCIInstance{id: 'a-inst', image_id: 'xla-a-image'})
        MERGE (c)-[:RESOURCE]->(:OCIInstance{id: 'a-inst-foreign', image_id: 'xla-b-image'})
        """,
        compartment=a['OCI_COMPARTMENT_ID'],
    )

    subnets = exposure_network.read_network(neo4j_session, a).subnets
    assert subnets['a-own'].igw_ids is not None
    assert subnets['a-foreign'].igw_ids is None

    identities = software.compute(neo4j_session, a)['OCIInstance']
    assert identities['a-inst']['software_identity'] == ['oracle-linux@8.9']
    assert identities['a-inst-foreign']['software_identity'] == []
