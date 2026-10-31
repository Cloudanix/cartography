import json

from cartography.intel.exposure.ports import PortSet
from cartography.intel.oci import api_gateway
from cartography.intel.oci import load_balancer
from cartography.intel.oci.exposure_layers import access
from cartography.intel.oci.exposure_layers import reach
from cartography.intel.oci.exposure_layers import software
from cartography.intel.oci.exposure_layers.network import default_route_igws
from cartography.intel.oci.exposure_layers.network import internet_open
from cartography.intel.oci.exposure_layers.network import Network
from cartography.intel.oci.exposure_layers.network import nsg_rule
from cartography.intel.oci.exposure_layers.network import ROUTE_UNRESOLVED
from cartography.intel.oci.exposure_layers.network import security_list_rules
from cartography.intel.oci.exposure_layers.network import SubnetFacts

WORLD = '0.0.0.0/0'
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


def _net(**subnet):
    facts = dict(vcn_id='vcn', security_list_ids=[], prohibit_public_ip=False, igw_ids=[IGW])
    facts.update(subnet)
    return Network(subnets={'s': SubnetFacts(**facts)}, igw_enabled={IGW: True}, rules={})


def test_internet_vias():
    assert _net().internet_vias('s') == [f'igw:{IGW}']
    assert _net(igw_ids=[]).internet_vias('s') == []
    assert _net(prohibit_public_ip=True).internet_vias('s') == []
    assert _net(igw_ids=None).internet_vias('s') == [ROUTE_UNRESOLVED]
    assert _net().internet_vias('unknown') == [ROUTE_UNRESOLVED]
    disabled = _net()
    disabled.igw_enabled[IGW] = False
    assert disabled.internet_vias('s') == []


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
