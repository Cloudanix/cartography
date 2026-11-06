import json

from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.oci import api_gateway
from cartography.intel.oci import load_balancer
from cartography.intel.oci.exposure_layers import access
from cartography.intel.oci.exposure_layers import blast_radius
from cartography.intel.oci.exposure_layers import reach
from cartography.intel.oci.exposure_layers import software
from cartography.intel.oci.exposure_layers.network import default_route_igws
from cartography.intel.oci.exposure_layers.network import internet_open
from cartography.intel.oci.exposure_layers.network import Network
from cartography.intel.oci.exposure_layers.network import nsg_rule
from cartography.intel.oci.exposure_layers.network import ROUTE_UNRESOLVED
from cartography.intel.oci.exposure_layers.network import security_list_rules
from cartography.intel.oci.exposure_layers.network import SubnetFacts
from cartography.intel.oci.exposure_layers.network import V4
from cartography.intel.oci.exposure_layers.network import V6

WORLD = '0.0.0.0/0'
V6_WORLD = '::/0'
GUA = '2603:c020:1:2::5'
IGW = 'ocid1.internetgateway.oc1.phx.a'


def _tcp(source, lo, hi=None, stateless=False):
    return {
        'protocol': '6', 'source': source, 'is-stateless': stateless,
        'tcp-options': {'destination-port-range': {'min': lo, 'max': hi or lo}},
    }


def _sl(ingress, egress=()):
    return security_list_rules(json.dumps(list(ingress)), json.dumps(list(egress)))


def test_security_list_ports_come_from_tcp_options_destination_range():
    rules = _sl([_tcp(WORLD, 8000, 8080), {'protocol': '17', 'source': WORLD}, {'protocol': '1', 'source': WORLD}])
    assert [r.ports.to_strings() for r in rules] == [['tcp:8000-8080'], ['udp:0-65535'], []]
    assert internet_open(_sl([{'protocol': 'all', 'source': WORLD}])) == PortSet.everything()


def test_rfc1918_only_rules_open_nothing_to_the_internet():
    assert internet_open(_sl([_tcp('10.0.0.0/16', 22), _tcp('::/0', 22)])).is_empty()


HTTPS_NSG_ROW = {
    'direction': 'INGRESS', 'protocol': '6', 'source': WORLD, 'tcp_dest_port_min': 443, 'tcp_dest_port_max': 443,
}


def test_nsg_rule_node_ports_and_direction():
    rule = nsg_rule(HTTPS_NSG_ROW)
    egress = nsg_rule({'direction': 'EGRESS', 'protocol': '17', 'destination': WORLD})
    assert (rule.ingress, rule.peer, rule.ports.to_strings()) == (True, WORLD, ['tcp:443-443'])
    assert (egress.ingress, egress.peer, egress.ports.to_strings()) == (False, WORLD, ['udp:0-65535'])


def test_security_list_and_nsg_rules_are_a_union():
    sl = _sl([_tcp(WORLD, 22)])
    nsg = [nsg_rule(HTTPS_NSG_ROW)]
    assert internet_open(sl + nsg).to_strings() == ['tcp:22-22', 'tcp:443-443']


def test_stateless_ingress_needs_an_egress_rule_for_replies():
    ingress = [_tcp(WORLD, 443, stateless=True)]
    assert internet_open(_sl(ingress)).is_empty()
    reply = {'protocol': '6', 'destination': WORLD, 'is-stateless': True}
    assert internet_open(_sl(ingress, [reply])).to_strings() == ['tcp:443-443']
    # Stateful ingress tracks its replies without any egress rule.
    assert internet_open(_sl([_tcp(WORLD, 22)])).to_strings() == ['tcp:22-22']


def test_stateless_return_must_cover_ephemeral_ports():
    reply_to_80_only = {
        'protocol': '6', 'destination': WORLD, 'tcp-options': {'destination-port-range': {'min': 80, 'max': 80}},
    }
    assert internet_open(_sl([_tcp(WORLD, 443, stateless=True)], [reply_to_80_only])).is_empty()


def test_default_route_igws_reads_ipv4_default_route_only():
    rules = json.dumps([
        {'destination': WORLD, 'network-entity-id': IGW},
        {'cidr-block': WORLD, 'network-entity-id': IGW + 'legacy'},
        {'destination': '::/0', 'network-entity-id': IGW + 'v6'},
        {'destination': WORLD, 'network-entity-id': 'ocid1.natgateway.oc1.phx.n'},
    ])
    assert default_route_igws(rules) == [IGW, IGW + 'legacy']


def _net(rules=(), **subnet):
    facts = dict(
        vcn_id='vcn', security_list_ids=['sl'], prohibit_public_ip=False, igw_ids={V4: [IGW], V6: []},
        route_table_id='rt',
    )
    facts.update(subnet)
    return Network(subnets={'s': SubnetFacts(**facts)}, igw_enabled={IGW: True}, rules={'sl': list(rules)})


def _routes(net, subnet='s', family=V4):
    reach_ = Reach()
    return list(net.routes(subnet, family, reach_)), reach_.blocked


def test_routes_and_their_blockers():
    assert _routes(_net()) == ([f'igw:{IGW}'], [])
    assert _routes(_net(igw_ids={V4: [], V6: []})) == (
        [], [{'hop': 'route', 'id': 'rt', 'reason': 'no_internet_route', 'detail': 'ipv4'}],
    )
    assert _routes(_net(prohibit_public_ip=True), family=V6) == (
        [], [{'hop': 'subnet', 'id': 's', 'reason': 'public_ip_prohibited', 'detail': 'ipv6'}],
    )
    assert _routes(_net(igw_ids=None)) == ([ROUTE_UNRESOLVED], [])
    assert _routes(_net(), 'unknown') == ([ROUTE_UNRESOLVED], [])
    disabled = _net()
    disabled.igw_enabled[IGW] = False
    assert _routes(disabled) == (
        [], [{
            'hop': 'route', 'id': 'rt', 'reason': 'no_internet_route',
            'detail': f'ipv4; internet gateway disabled: {IGW}',
        }],
    )


def test_default_route_igws_per_family():
    v4_route = {'destination': WORLD, 'network-entity-id': IGW}
    v6_route = {'destination': V6_WORLD, 'network-entity-id': IGW + 'v6'}
    assert default_route_igws(json.dumps([v4_route, v6_route]), V6) == [IGW + 'v6']
    assert default_route_igws(json.dumps([v4_route]), V6) == []


def test_rules_of_one_family_do_not_open_the_other():
    rules = _sl([_tcp(WORLD, 22), _tcp(V6_WORLD, 443)])
    assert internet_open(rules).to_strings() == ['tcp:22-22']
    assert internet_open(rules, V6).to_strings() == ['tcp:443-443']


DUAL_ROUTES = {V4: [IGW], V6: [IGW]}


def _vnic(**row):
    return {'subnet_id': 's', 'nsg_ids': [], 'public_ip': None, 'ipv6_addresses': [GUA], **row}


def test_ipv6_address_route_and_rule_is_reachable():
    reach_ = reach.vnic_reach(_vnic(), _net(_sl([_tcp(V6_WORLD, 443)]), igw_ids=DUAL_ROUTES))
    props = reach_.props()
    assert {k: props[k] for k in list(props)[:4]} == {
        'public_reasons': ['public_ipv6'], 'internet_reachable': True,
        'internet_reachable_ports': ['tcp:443-443'], 'internet_reachable_via': ['direct_ipv6'],
    }


def test_ipv6_address_with_only_ipv4_world_rule_is_not_reachable():
    reach_ = reach.vnic_reach(_vnic(), _net(_sl([_tcp(WORLD, 443)]), igw_ids=DUAL_ROUTES))
    assert (reach_.props()['public_reasons'], reach_.props()['internet_reachable']) == (['public_ipv6'], False)


def test_ipv6_without_default_v6_route_is_not_reachable():
    # Only the IPv4 default route reaches the IGW.
    reach_ = reach.vnic_reach(_vnic(), _net(_sl([_tcp(V6_WORLD, 443)])))
    assert reach_.props()['internet_reachable'] is False


def test_stateless_ipv6_needs_ipv6_return_egress():
    ingress = [_tcp(V6_WORLD, 443, stateless=True)]
    v4_reply = {'protocol': '6', 'destination': WORLD, 'is-stateless': True}
    v6_reply = {'protocol': '6', 'destination': V6_WORLD, 'is-stateless': True}
    assert reach.vnic_reach(_vnic(), _net(_sl(ingress, [v4_reply]), igw_ids=DUAL_ROUTES)).ports.is_empty()
    reachable = reach.vnic_reach(_vnic(), _net(_sl(ingress, [v6_reply]), igw_ids=DUAL_ROUTES))
    assert reachable.ports.to_strings() == ['tcp:443-443']


def test_only_global_ipv6_addresses_are_public():
    net = _net(_sl([_tcp(V6_WORLD, 443)]), igw_ids=DUAL_ROUTES)
    assert reach.vnic_reach(_vnic(ipv6_addresses=['fd00::5', 'fe80::1', 'bogus']), net).props()['public_reasons'] == []
    # A dual-stack VNIC reports both families; the IPv4 path keeps naming the gateway.
    dual_net = _net(_sl([_tcp(WORLD, 22), _tcp(V6_WORLD, 443)]), igw_ids=DUAL_ROUTES)
    dual = reach.vnic_reach(_vnic(public_ip='203.0.113.1'), dual_net).props()
    assert dual['internet_reachable_ports'] == ['tcp:22-22', 'tcp:443-443']
    assert dual['internet_reachable_via'] == ['direct_ipv6', f'igw:{IGW}']
    assert dual['public_reasons'] == ['public_ip', 'public_ipv6']


def _context(reach_):
    props = reach_.props()
    return json.loads(props['exposure_paths']), json.loads(props['exposure_blocked_by'])


def test_paths_name_entry_gateway_route_and_pooled_filters():
    net = _net(_sl([_tcp(WORLD, 22), _tcp(V6_WORLD, 443)]), igw_ids=DUAL_ROUTES)
    paths, blocked = _context(reach.vnic_reach(_vnic(public_ip='203.0.113.1', nsg_ids=['nsg']), net))
    filters = [{'hop': 'security_list', 'id': 'sl'}, {'hop': 'nsg', 'id': 'nsg'}]
    assert paths == [
        {
            'via': 'direct_ipv6', 'entry': {'type': 'public_ipv6', 'id': GUA}, 'ports': ['tcp:443-443'],
            'hops': [
                {'hop': 'internet_gateway', 'id': IGW}, {'hop': 'route', 'id': 'rt', 'rule': f'::/0 -> {IGW}'},
            ] + filters,
        },
        {
            'via': f'igw:{IGW}', 'entry': {'type': 'public_ip', 'id': '203.0.113.1'}, 'ports': ['tcp:22-22'],
            'hops': [
                {'hop': 'internet_gateway', 'id': IGW}, {'hop': 'route', 'id': 'rt', 'rule': f'0.0.0.0/0 -> {IGW}'},
            ] + filters,
        },
    ]
    assert blocked == []


def test_blocked_by_names_the_filters_and_the_family():
    # No world rule: the pooled security lists and NSGs are named together.
    rfc1918 = reach.vnic_reach(_vnic(public_ip='203.0.113.1', nsg_ids=['nsg']), _net(_sl([_tcp('10.0.0.0/16', 22)])))
    assert _context(rfc1918) == (
        [], [
            {'hop': 'security_list', 'id': 'sl,nsg', 'reason': 'not_allowed', 'detail': 'ipv4'},
            {'hop': 'route', 'id': 'rt', 'reason': 'no_internet_route', 'detail': 'ipv6'},
        ],
    )
    stateless = reach.vnic_reach(
        _vnic(ipv6_addresses=[], public_ip='203.0.113.1'), _net(
            _sl([
                _tcp(WORLD, 443, stateless=True),
            ]),
        ),
    )
    assert _context(stateless)[1] == [
        {'hop': 'security_list', 'id': 'sl', 'reason': 'return_path_denied', 'detail': 'ipv4'},
    ]


def test_load_balancer_blocker_carries_listener_ports():
    row = {'id': 'lb', 'private': False, 'subnets': ['s'], 'nsgs': [], 'listeners': ['6:443']}
    paths, blocked = _context(reach.load_balancer_reach(row, _net(_sl([_tcp(WORLD, 22)]))))
    assert (paths, blocked) == (
        [], [
            {'hop': 'security_list', 'id': 'sl', 'reason': 'not_allowed', 'ports': ['tcp:443-443'], 'detail': 'ipv4'},
        ],
    )
    open_paths, _ = _context(reach.load_balancer_reach(row, _net(_sl([_tcp(WORLD, 443)]))))
    assert open_paths[0]['entry'] == {'type': 'load_balancer', 'id': 'lb', 'listener_ports': ['tcp:443-443']}


def test_owner_merges_paths_and_blockers_of_its_vnics():
    net = _net(_sl([_tcp(WORLD, 22)]))
    rows = [
        {'owner': 'i', 'id': 'v1', 'subnet_id': 's', 'nsg_ids': [], 'public_ip': '203.0.113.1'},
        {'owner': 'i', 'id': 'v2', 'subnet_id': 's', 'nsg_ids': [], 'public_ip': '203.0.113.2'},
    ]
    owners, vnics = reach.vnic_owners(rows, net)
    paths, _ = _context(owners['i'])
    # Same gateway: one path, first VNIC's entry.
    assert [(p['via'], p['entry']['id'], p['ports']) for p in paths] == [(f'igw:{IGW}', '203.0.113.1', ['tcp:22-22'])]
    closed = _net(prohibit_public_ip=True)
    owners, _ = reach.vnic_owners(rows[:1], closed)
    prohibited = {'hop': 'subnet', 'id': 's', 'reason': 'public_ip_prohibited', 'detail': 'ipv4'}
    assert _context(owners['i'])[1] == [prohibited]


def test_listener_ports_and_backend_endpoints():
    assert reach.listener_ports(['6:443', '17:53']).to_strings() == ['tcp:443-443', 'udp:53-53']
    assert reach.listener_ports(['any:0']) == PortSet.everything()
    row = {'endpoints': ['10.0.1.5:8080', 'ocid1.instance.oc1.phx.i:0'], 'addresses': []}
    assert reach.backend_endpoints(row) == [('10.0.1.5', 8080), ('ocid1.instance.oc1.phx.i', None)]
    assert reach.backend_endpoints({'endpoints': None, 'addresses': ['10.0.1.5']}) == [('10.0.1.5', None)]


def test_load_balancer_transform_records_backend_endpoints():
    lb = {'id': 'lb', 'backend-sets': {'web': {'backends': [{'ip-address': '10.0.1.5', 'port': 8080}]}}}
    backend = {'target-id': 'ocid1.instance.x', 'ip-address': '10.0.2.7', 'port': 0}
    nlb = {'id': 'nlb', 'backend-sets': {'p': {'backends': [backend]}}}
    assert load_balancer.transform_load_balancers([lb], 'r')[0]['backend_endpoints'] == ['10.0.1.5:8080']
    assert load_balancer.transform_network_load_balancers([nlb], 'r')[0]['backend_endpoints'] == [
        '10.0.2.7:0', 'ocid1.instance.x:0',
    ]


def test_autonomous_database_reach():
    rows = [
        {'id': 'open', 'public': True, 'dedicated': False, 'acl': []},
        {'id': 'world', 'public': True, 'dedicated': False, 'acl': [WORLD]},
        {'id': 'acl', 'public': True, 'dedicated': False, 'acl': ['203.0.113.0/24']},
        {'id': 'dedicated', 'public': True, 'dedicated': True, 'acl': []},
        {'id': 'private', 'public': False, 'dedicated': False, 'acl': []},
    ]
    out = reach.autonomous_databases(rows)
    assert {k: v.props()['internet_reachable'] for k, v in out.items()} == {
        'open': True, 'world': True, 'acl': False, 'dedicated': False, 'private': False,
    }
    assert out['acl'].props()['public_reasons'] == ['public_endpoint']
    assert _context(out['acl'])[1] == [{
        'hop': 'firewall', 'id': 'acl', 'reason': 'not_allowed', 'ports': ['tcp:443-443', 'tcp:1521-1522'],
        'detail': 'access_control_list',
    }]
    assert _context(out['open'])[0][0]['entry'] == {'type': 'public_endpoint', 'id': 'open'}


def test_blast_radius_rows_name_the_admitting_filter():
    db_rule = {**HTTPS_NSG_ROW, 'source': 'app-nsg', 'tcp_dest_port_min': 1521, 'tcp_dest_port_max': 1521}
    net = Network(
        subnets={'db': SubnetFacts('vcn', ['sl'], True, None)}, igw_enabled={},
        rules={'sl': _sl([_tcp('10.0.0.0/16', 1521)]), 'db-nsg': [nsg_rule(db_rule)]},
    )
    store = {'id': 'd', 'subnet': 'db', 'nsgs': ['db-nsg'], 'port_min': 1521, 'port_max': 1521}
    by_nsg = {'id': 'i', 'ips': ['10.0.1.5'], 'nsgs': {'app-nsg'}, 'vcns': {'vcn'}}
    by_cidr = {**by_nsg, 'id': 'j', 'nsgs': set()}
    rows = blast_radius.reach_rows([by_nsg, by_cidr], [store], net, 'OCIDbSystem')
    common = {'dst': 'd', 'dst_type': 'OCIDbSystem', 'ports': ['tcp:1521-1521']}
    assert rows == [
        {**common, 'src': 'i', 'via': 'network_security_group', 'admitted_by': 'db-nsg'},
        {**common, 'src': 'j', 'via': 'cidr', 'admitted_by': 'sl'},
    ]


def test_api_deployment_anonymous_verdicts():
    anonymous_route = {'request-policies': {'authorization': {'type': 'ANONYMOUS'}}}
    authenticated = {'type': 'JWT_AUTHENTICATION', 'is-anonymous-access-allowed': True}
    assert api_gateway.allows_anonymous({'specification': {'routes': [{}]}})
    assert api_gateway.allows_anonymous({
        'specification': {'request-policies': {'authentication': authenticated}, 'routes': [anonymous_route]},
    })
    assert not api_gateway.allows_anonymous({
        'specification': {'request-policies': {'authentication': authenticated}, 'routes': [{}]},
    })
    assert not api_gateway.allows_anonymous({
        'specification': {
            'request-policies': {'authentication': {**authenticated, 'is-anonymous-access-allowed': False}},
            'routes': [anonymous_route],
        },
    })
    assert not api_gateway.allows_anonymous({
        'specification': {'request-policies': {'mutual-tls': {'is-verified-certificate-required': True}}},
    })


def test_transform_gateways_keeps_not_ingested_apart_from_no_deployments():
    gw = [{'id': 'gw'}]
    assert api_gateway.transform_gateways(gw, 'r')[0]['deployment_ids'] is None
    assert api_gateway.transform_gateways(gw, 'r', [])[0]['deployment_ids'] == []
    open_dep = {'id': 'd1', 'gateway-id': 'gw', 'specification': {}}
    row = api_gateway.transform_gateways(gw, 'r', [open_dep])[0]
    assert (row['deployment_ids'], row['anonymous_deployment_ids']) == (['d1'], ['d1'])


def test_auth_verdicts():
    assert access.api_gateway_auth({'deployments': None, 'anonymous': False})[0] == 'unknown'
    assert access.api_gateway_auth({'deployments': ['d'], 'anonymous': True})[0] == 'none'
    assert access.api_gateway_auth({'deployments': ['d'], 'anonymous': False})[0] == 'required'
    assert access.bucket_auth({'open': True, 'par': False}) == ('none', ['public_access_type'])
    assert access.bucket_auth({'open': False, 'par': True}) == ('required', ['iam', 'unexpired_read_par'])
    assert access.autonomous_db_auth({'mtls': True}) == ('required', ['database_credentials', 'mtls_wallet'])


def test_software_identities():
    assert software.kubernetes('v1.29.1') == 'kubernetes@1.29.1'
    assert software.kubernetes(None) is None
    assert software.instance_os({'image': 'Oracle-Linux-8.9-2024.01.26-0'}) == 'oracle-linux@8.9'
    assert software.instance_os({'image': None, 'os': 'canonical ubuntu', 'os_version': '22.04'}) == 'ubuntu@22.04'
    windows = 'Windows-Server-2019-Standard-Edition-VM-2024.01.09-0'
    assert software.instance_os({'image': windows}) == 'windows-server@2019'
    assert software.instance_os({}) is None
