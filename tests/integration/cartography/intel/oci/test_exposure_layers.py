"""
End-to-end check of the OCI exposure layers on a graph written by the real OCI loaders.
Scenarios follow docs/exposure-layers/plan.md section 8 where the construct exists in OCI.
"""
import pytest

from cartography.intel.oci import api_gateway
from cartography.intel.oci import database
from cartography.intel.oci import exposure_layers
from cartography.intel.oci import load_balancer
from cartography.intel.oci import network
from cartography.intel.oci import oke
from cartography.intel.oci import storage

WS, TENANCY, COMPARTMENT = 'ws-oci-xl', 'ocid1.tenancy.oc1..xl', 'ocid1.compartment.oc1..xl'
OTHER_WS, OTHER_TENANCY, OTHER_COMPARTMENT = 'ws-oci-xl-other', 'ocid1.tenancy.oc1..xlo', 'ocid1.compartment.oc1..xlo'
REGION = 'us-phoenix-1'
TAG = 1700000000
PARAMS = {'UPDATE_TAG': TAG, 'WORKSPACE_ID': WS, 'OCI_TENANCY_ID': TENANCY, 'OCI_COMPARTMENT_ID': COMPARTMENT}
VCN = 'xl-vcn'
IGW = 'ocid1.internetgateway.oc1.phx.xl'
NAT = 'ocid1.natgateway.oc1.phx.xl'
WORLD = '0.0.0.0/0'
VCN_CIDR = '10.0.0.0/16'
UNTOUCHED = 'untouched'


def _tcp(source, lo, hi=None, **extra):
    return {
        'protocol': '6', 'source': source, 'source-type': 'CIDR_BLOCK',
        'tcp-options': {'destination-port-range': {'min': lo, 'max': hi or lo}}, **extra,
    }


SECURITY_LISTS = {
    'xl-sl-open': [_tcp(WORLD, 22), _tcp(WORLD, 443)],
    'xl-sl-rfc1918': [{'protocol': 'all', 'source': VCN_CIDR}],
    'xl-sl-stateless': [_tcp(WORLD, 443, **{'is-stateless': True})],
    'xl-sl-closed': [],
    'xl-sl-backend': [_tcp(VCN_CIDR, 8080)],
}
NSGS = {
    'xl-nsg-https': [_tcp(WORLD, 443)],
    'xl-nsg-app': [],
    'xl-nsg-db': [_tcp('xl-nsg-app', 1521, **{'source-type': 'NETWORK_SECURITY_GROUP'})],
}
# subnet -> (security list, route target, prohibit public IP)
SUBNETS = {
    'xl-pub-open': ('xl-sl-open', IGW, False),
    'xl-pub-rfc1918': ('xl-sl-rfc1918', IGW, False),
    'xl-noroute': ('xl-sl-open', NAT, False),
    'xl-pub-stateless': ('xl-sl-stateless', IGW, False),
    'xl-pub-closed': ('xl-sl-closed', IGW, False),
    'xl-private': ('xl-sl-backend', NAT, True),
    'xl-lb': ('xl-sl-open', IGW, False),
}


def _run(session, query, **kw):
    session.run(query, **kw).consume()


def _tenancy(session, ws, tenancy, compartment):
    _run(
        session,
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(t:OCITenancy{id: $tenancy}) "
        "MERGE (t)-[:OWNER]->(:OCICompartment{id: $compartment})",
        ws=ws, tenancy=tenancy, compartment=compartment,
    )


def _network(session):
    args = (TENANCY, COMPARTMENT, REGION, TAG)
    network.load_vcns(session, [{'id': VCN, 'compartment-id': COMPARTMENT}], *args)
    network.load_security_lists(
        session, [{'id': i, 'vcn-id': VCN, 'ingress-security-rules': r} for i, r in SECURITY_LISTS.items()], *args,
    )
    network.load_internet_gateways(session, [{'id': IGW, 'vcn-id': VCN, 'is-enabled': True}], *args)
    for nsg_id, rules in NSGS.items():
        network.load_network_security_groups(session, [{'id': nsg_id, 'vcn-id': VCN}], *args)
        network.load_nsg_security_rules(
            session, [{'id': f'{nsg_id}.r{i}', 'direction': 'INGRESS', **r} for i, r in enumerate(rules)], nsg_id, TAG,
        )
    for subnet_id, (sl_id, target, prohibit) in SUBNETS.items():
        network.load_route_tables(
            session,
            [{
                'id': f'rt-{subnet_id}', 'vcn-id': VCN,
                'route-rules': [{'destination': WORLD, 'network-entity-id': target}],
            }],
            *args,
        )
        network.load_subnets(
            session,
            [{
                'id': subnet_id, 'vcn-id': VCN, 'security-list-ids': [sl_id], 'route-table-id': f'rt-{subnet_id}',
                'prohibit-public-ip-on-vnic': prohibit,
            }],
            *args,
        )


def _instance(session, instance_id, subnet_id, public_ip=None, private_ip=None, nsgs=(), compartment=COMPARTMENT):
    vnic_id = f'{instance_id}.vnic'
    _run(
        session,
        """
        MATCH (c:OCICompartment{id: $compartment})
        MERGE (c)-[:RESOURCE]->(i:OCIInstance{id: $instance_id})
        MERGE (i)-[:OCI_VNIC_ATTACHMENT]->(:OCIVnicAttachment{id: $vnic_id + '.att', vnic_id: $vnic_id})
        """,
        compartment=compartment, instance_id=instance_id, vnic_id=vnic_id,
    )
    network.load_vnics(
        session,
        [{
            'id': vnic_id, 'subnet-id': subnet_id, 'public-ip': public_ip, 'private-ip': private_ip,
            'nsg-ids': list(nsgs),
        }],
        REGION, TAG,
    )


def _instances(session):
    _instance(session, 'xl-i-open', 'xl-pub-open', public_ip='203.0.113.1')
    _instance(session, 'xl-i-rfc1918', 'xl-pub-rfc1918', public_ip='203.0.113.2')
    _instance(session, 'xl-i-noroute', 'xl-noroute', public_ip='203.0.113.3')
    _instance(session, 'xl-i-stateless', 'xl-pub-stateless', public_ip='203.0.113.4')
    _instance(session, 'xl-i-nsg', 'xl-pub-closed', public_ip='203.0.113.5', nsgs=['xl-nsg-https'])
    _instance(session, 'xl-i-private', 'xl-private', private_ip='10.0.5.5', nsgs=['xl-nsg-app'])
    _run(
        session,
        "MATCH (i:OCIInstance{id: 'xl-i-open'}) SET i.image_id = 'xl-img', i.exposed_internet = $u "
        "MERGE (:OCIImage{id: 'xl-img', display_name: 'Oracle-Linux-8.9-2024.01.26-0'}) "
        "WITH i MATCH (s:OCIInstance{id: 'xl-i-rfc1918'}) SET s.internet_reachable = true",
        u=UNTOUCHED,
    )


def _load_balancer(session):
    lb = {
        'id': 'xl-lb', 'is-private': False, 'subnet-ids': ['xl-lb'],
        'listeners': {'https': {'port': 443, 'protocol': 'HTTP'}},
        'backend-sets': {'web': {'backends': [{'ip-address': '10.0.5.5', 'port': 8080}]}},
    }
    rows = load_balancer.transform_load_balancers([lb], REGION)
    load_balancer.load_load_balancers(session, rows, load_balancer.LOAD_BALANCER_LABEL, COMPARTMENT, TAG)


def _databases(session):
    database.load_db_systems(
        session,
        database.transform_db_systems(
            [{
                'id': 'xl-db', 'lifecycle-state': 'AVAILABLE', 'subnet-id': 'xl-private', 'nsg-ids': ['xl-nsg-db'],
                'listener-port': 1521, 'version': '19.0.0.0',
            }],
            REGION,
        ),
        COMPARTMENT, TAG,
    )
    database.load_db_homes(
        session,
        database.transform_db_homes(
            [{'id': 'xl-db-home', 'lifecycle-state': 'AVAILABLE', 'db-system-id': 'xl-db', 'db-version': '19.22.0.0'}],
            REGION,
        ),
        TAG,
    )
    adbs = [{'id': 'xl-adb-open'}, {'id': 'xl-adb-acl', 'whitelisted-ips': ['198.51.100.7']}]
    database.load_autonomous_databases(
        session,
        database.transform_autonomous_databases([{'lifecycle-state': 'AVAILABLE', **a} for a in adbs], REGION),
        COMPARTMENT, TAG,
    )
    # Left over from an earlier sync: the DB no longer admits this instance.
    _run(
        session,
        "MATCH (i:OCIInstance{id: 'xl-i-open'}), (d:OCIDbSystem{id: 'xl-db'}) "
        "MERGE (i)-[:CAN_NETWORK_REACH {lastupdated: $old}]->(d)",
        old=TAG - 1,
    )


def _managed(session):
    details = {
        'xl-b-public': {'public-access-type': 'ObjectRead'},
        'xl-b-private': {'public-access-type': 'NoPublicAccess'},
    }
    storage.load_buckets(
        session,
        storage.transform_buckets([{'name': n, 'id': n} for n in details], details, 'ns', REGION, {}),
        COMPARTMENT, TAG,
    )
    cluster = {
        'id': 'xl-oke', 'lifecycle-state': 'ACTIVE', 'kubernetes-version': 'v1.29.1',
        'endpoint-config': {'subnet-id': 'xl-pub-open', 'is-public-ip-enabled': True},
    }
    oke.load_clusters(session, oke.transform_clusters([cluster], {}, REGION), COMPARTMENT, TAG)
    gateways = api_gateway.transform_gateways(
        [{'id': 'xl-gw', 'endpoint-type': 'PUBLIC', 'subnet-id': 'xl-lb'}], REGION,
        [{'id': 'xl-dep', 'gateway-id': 'xl-gw', 'specification': {'routes': [{}]}}],
    )
    api_gateway.load_gateways(session, gateways, COMPARTMENT, TAG)


def _other_workspace(session):
    _tenancy(session, OTHER_WS, OTHER_TENANCY, OTHER_COMPARTMENT)
    _instance(session, 'xl-other-i', 'xl-pub-open', public_ip='203.0.113.9', compartment=OTHER_COMPARTMENT)
    _run(session, "MATCH (i:OCIInstance{id: 'xl-other-i'}) SET i.internet_reachable = $u", u=UNTOUCHED)


@pytest.fixture(scope='module')
def graph(neo4j_session):
    _tenancy(neo4j_session, WS, TENANCY, COMPARTMENT)
    _network(neo4j_session)
    _instances(neo4j_session)
    _load_balancer(neo4j_session)
    _databases(neo4j_session)
    _managed(neo4j_session)
    _other_workspace(neo4j_session)
    exposure_layers.run(neo4j_session, PARAMS)
    return neo4j_session


def _props(session, label, node_id):
    row = session.run(f"MATCH (n:{label}{{id: $id}}) RETURN properties(n) AS p", id=node_id).single()
    return row['p']


def _reach(session, label, node_id):
    p = _props(session, label, node_id)
    return p['internet_reachable'], p['internet_reachable_ports'], p['public_reasons']


def test_open_security_list_and_public_ip_is_reachable(graph):
    p = _props(graph, 'OCIInstance', 'xl-i-open')
    assert (p['internet_reachable'], p['internet_reachable_ports']) == (True, ['tcp:22-22', 'tcp:443-443'])
    assert (p['public_reasons'], p['internet_reachable_via']) == (['public_ip'], [f'igw:{IGW}'])
    assert _props(graph, 'OCIVnic', 'xl-i-open.vnic')['internet_reachable'] is True
    # Legacy flag is never touched.
    assert p['exposed_internet'] == UNTOUCHED


def test_public_ip_but_closed_path_is_public_not_reachable(graph):
    # RFC1918-only rules (and a stale true rewritten), no IGW route, stateless ingress without egress.
    for instance in ('xl-i-rfc1918', 'xl-i-noroute', 'xl-i-stateless'):
        assert _reach(graph, 'OCIInstance', instance) == (False, [], ['public_ip']), instance


def test_nsg_allows_while_security_list_does_not(graph):
    assert _reach(graph, 'OCIInstance', 'xl-i-nsg') == (True, ['tcp:443-443'], ['public_ip'])


def test_private_instance_behind_public_load_balancer(graph):
    assert _reach(graph, 'OCILoadBalancer', 'xl-lb') == (True, ['tcp:443-443'], ['public_load_balancer'])
    p = _props(graph, 'OCIInstance', 'xl-i-private')
    assert (p['internet_reachable'], p['internet_reachable_ports'], p['internet_reachable_via']) == (
        True, ['tcp:8080-8080'], ['lb:xl-lb'],
    )
    assert p['public_reasons'] == []
    assert _props(graph, 'OCILoadBalancer', 'xl-lb')['access_auth'] == 'unknown'


def test_buckets(graph):
    public = _props(graph, 'OCIStorageBucket', 'xl-b-public')
    private = _props(graph, 'OCIStorageBucket', 'xl-b-private')
    assert (public['internet_reachable'], public['access_auth'], public['public_reasons']) == (
        True, 'none', ['public_access_type'],
    )
    assert (private['internet_reachable'], private['access_auth'], private['public_reasons']) == (True, 'required', [])


def test_autonomous_database_acl(graph):
    assert _reach(graph, 'OCIAutonomousDatabase', 'xl-adb-open') == (
        True, ['tcp:443-443', 'tcp:1521-1522'], ['public_endpoint'],
    )
    assert _reach(graph, 'OCIAutonomousDatabase', 'xl-adb-acl') == (False, [], ['public_endpoint'])
    assert _props(graph, 'OCIAutonomousDatabase', 'xl-adb-acl')['access_auth'] == 'required'


def test_managed_endpoints_auth_and_software(graph):
    cluster = _props(graph, 'OCIOKECluster', 'xl-oke')
    # Public endpoint, but its subnet's security list does not open 6443.
    assert (cluster['internet_reachable'], cluster['public_reasons'], cluster['access_auth']) == (
        False, ['public_endpoint'], 'required',
    )
    assert (cluster['software_identity'], cluster['software_identity_source']) == (
        ['kubernetes@1.29.1'], 'managed_config',
    )
    gw = _props(graph, 'OCIApiGateway', 'xl-gw')
    assert (gw['internet_reachable_ports'], gw['access_auth'], gw['access_auth_reasons']) == (
        ['tcp:443-443'], 'none', ['anonymous_deployment'],
    )
    db = _props(graph, 'OCIDbSystem', 'xl-db')
    assert (db['access_auth'], db['software_identity']) == (
        'required', ['oracle-database@19.0.0.0', 'oracle-database@19.22.0.0'],
    )
    instance = _props(graph, 'OCIInstance', 'xl-i-open')
    assert (instance['software_identity'], instance['software_identity_source']) == (['oracle-linux@8.9'], 'image_name')


def test_network_reach_edges_and_stale_cleanup(graph):
    rows = graph.run(
        "MATCH (i:OCIInstance)-[r:CAN_NETWORK_REACH]->(d) WHERE i.id STARTS WITH 'xl-' "
        "RETURN i.id AS src, d.id AS dst, r.ports AS ports, r.via AS via",
    )
    assert sorted((r['src'], r['dst'], r['ports'], r['via']) for r in rows) == [
        ('xl-i-private', 'xl-db', ['tcp:1521-1521'], 'network_security_group'),
    ]


def test_other_workspace_untouched(graph):
    assert _props(graph, 'OCIInstance', 'xl-other-i')['internet_reachable'] == UNTOUCHED
