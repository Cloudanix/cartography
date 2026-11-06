"""
Exposure-layer reads resolve ids only inside the syncing tenancy (AGENTS.md "Tenant isolation"): a
route table or image id that tenancy B holds is unknown to tenancy A's evaluation. Inside one tenancy
they stay in the compartment being analysed: each compartment is its own Cloudanix entity.
"""
from cartography.intel.oci.exposure_layers import blast_radius
from cartography.intel.oci.exposure_layers import network as exposure_network
from cartography.intel.oci.exposure_layers import reach
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


def test_layers_read_only_the_compartment_under_analysis(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    app = seed_tenancy(neo4j_session, 'cmp')
    network_compartment = 'ocid1.compartment.oc1..cmp-net'
    # A shared network compartment of the same tenancy and workspace: another entity.
    neo4j_session.run(
        "MATCH (t:OCITenancy{id: $tenancy}) MERGE (t)-[:OWNER]->(:OCICompartment{id: $compartment})",
        tenancy=app['OCI_TENANCY_ID'], compartment=network_compartment,
    )
    _seed(neo4j_session, 'cmp-app', app)
    _seed(neo4j_session, 'cmp-net', {'OCI_COMPARTMENT_ID': network_compartment})
    neo4j_session.run(
        """
        MATCH (app:OCICompartment{id: $app}), (net:OCICompartment{id: $net})
        MATCH (app)-[:RESOURCE]->(av:OCIVcn{id: 'cmp-app-vcn'}), (net)-[:RESOURCE]->(nv:OCIVcn{id: 'cmp-net-vcn'})
        MERGE (av)-[:OCI_SUBNET]->(:OCISubnet{id: 'app-subnet', route_table_id: 'cmp-app-rt'})
        MERGE (nv)-[:OCI_SUBNET]->(:OCISubnet{id: 'shared-subnet', route_table_id: 'cmp-net-rt'})
        MERGE (app)-[:RESOURCE]->(:OCILoadBalancer{id: 'app-lb'})
        MERGE (net)-[:RESOURCE]->(:OCILoadBalancer{id: 'net-lb'})
        MERGE (app)-[:RESOURCE]->(:OCIDbSystem{id: 'app-db'})
        MERGE (net)-[:RESOURCE]->(:OCIDbSystem{id: 'net-db'})
        MERGE (app)-[:RESOURCE]->(:OCIInstance{id: 'app-inst-net-image', image_id: 'cmp-net-image'})
        """,
        app=app['OCI_COMPARTMENT_ID'], net=network_compartment,
    )

    assert set(exposure_network.read_network(neo4j_session, app).subnets) == {'app-subnet'}
    assert [r['id'] for r in neo4j_session.run(reach._LB_QUERY, **app)] == ['app-lb']
    assert [r['id'] for r in neo4j_session.run(blast_radius.STORES['OCIDbSystem'], **app)] == ['app-db']
    identities = software.compute(neo4j_session, app)['OCIInstance']
    assert identities['app-inst-net-image']['software_identity'] == []
