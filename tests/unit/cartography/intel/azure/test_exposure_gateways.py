"""
Azure exposure layers through front doors (App Gateway, Azure Firewall DNAT) and the L3
verdicts for Easy Auth and WAF. Pure functions only; the graph run is in the integration test.
"""
from cartography.intel.azure.compute import _vmss_front_doors
from cartography.intel.azure.exposure_layers.access import app_gateway
from cartography.intel.azure.exposure_layers.access import easy_auth
from cartography.intel.azure.exposure_layers.gateways import app_gateways
from cartography.intel.azure.exposure_layers.gateways import Backends
from cartography.intel.azure.exposure_layers.gateways import dnat_from_world
from cartography.intel.azure.exposure_layers.gateways import firewalls
from cartography.intel.azure.exposure_layers.gateways import nics_by_ip
from cartography.intel.azure.exposure_layers.gateways import ports_of
from cartography.intel.azure.exposure_layers.gateways import resolve_ip
from cartography.intel.azure.exposure_layers.network import nsg_open
from cartography.intel.azure.exposure_layers.network import nsg_open_from
from cartography.intel.azure.exposure_layers.network import source_covers
from cartography.intel.azure.exposure_layers.network import SubnetFacts
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet

AGW_SUBNET = ['10.0.50.0/24']
NIC = 'NIC'


def _rule(priority, access='Allow', source='Internet', ports='*', protocol='Tcp'):
    return {
        'direction': 'Inbound', 'access': access, 'priority': priority, 'protocol': protocol,
        'source_address_prefix': source, 'destination_port_range': ports,
    }


def test_vmss_front_doors_app_gateway_pools():
    pool = {'id': '/AGW/backendAddressPools/Web'}
    nic_config = {'ip_configurations': [{'application_gateway_backend_address_pools': [pool]}]}
    scale_set = {'virtual_machine_profile': {'network_profile': {'network_interface_configurations': [nic_config]}}}
    doors = _vmss_front_doors(scale_set)
    assert (doors['appgw_backend_pool_ids'], doors['lb_backend_pool_ids']) == (['/agw/backendaddresspools/web'], [])


def test_source_covers_front_door_subnet():
    assert source_covers('VirtualNetwork', AGW_SUBNET)
    assert source_covers('*', AGW_SUBNET)
    assert source_covers('0.0.0.0/0', AGW_SUBNET)
    assert not source_covers('Internet', AGW_SUBNET)  # service tag: addresses outside the VNet
    assert source_covers('10.0.0.0/16', AGW_SUBNET)
    assert not source_covers('10.0.50.0/25', AGW_SUBNET)  # half the subnet: no match (ponytail)
    assert not source_covers('AzureLoadBalancer', AGW_SUBNET)
    assert not source_covers('10.0.0.0/16', [])  # prefix not ingested: only world / VirtualNetwork match
    assert not source_covers('fd00::/8', AGW_SUBNET)


def test_nsg_open_from_uses_allow_vnet_default():
    # No custom rule: the implied AllowVnetInBound (65000) admits the gateway subnet.
    assert nsg_open_from([], AGW_SUBNET) == PortSet.everything()
    # Internet-only rules do not matter, a deny on the gateway range does.
    rules = [_rule(100, ports='443'), _rule(110, access='Deny', source='10.0.50.0/24', ports='8080')]
    assert (PortSet.of('tcp', 8080, 8080) & nsg_open_from(rules, AGW_SUBNET)).is_empty()
    # Internet sources are unaffected by the VNet default.
    assert nsg_open([_rule(100, source='VirtualNetwork')]).is_empty()
    # A deny below the default's priority never decides.
    assert nsg_open_from([_rule(65100, access='Deny', source='*', protocol='*')], AGW_SUBNET) == PortSet.everything()


def _backends(results, nics=(), by_ipconfig=None, nsg_rules=None, subnets=None):
    """nics: (id, private ip, subnet id, NIC NSG ids)."""
    rows = [{'id': n, 'private_ips': [ip], 'subnets': [s], 'nsgs': list(g)} for n, ip, s, g in nics]
    nsg_rules = nsg_rules or {}
    return Backends(
        by_ipconfig=by_ipconfig or {}, by_pool={}, by_ip=nics_by_ip(rows, NIC),
        members={(NIC, r['id']): (r['subnets'], r['nsgs']) for r in rows},
        subnets=subnets or {}, nsg_rules=nsg_rules,
        world_nsgs={i: nsg_open(r) for i, r in nsg_rules.items()}, results=results,
    )


def test_resolve_ip_prefers_front_door_vnet_and_refuses_ambiguity():
    backends = _backends(
        {}, [
            ('a', '10.0.0.4', 'vnet-a/subnets/s', []),
            ('b', '10.0.0.4', 'vnet-b/subnets/s', []),
            ('c', '10.0.0.4', 'vnet-c/subnets/s', []),
            ('only', '10.9.9.9', 'vnet-c/subnets/s', []),
        ],
    )
    assert resolve_ip('10.9.9.9', backends, set()) == (NIC, 'only')
    assert resolve_ip('10.0.0.4', backends, {'vnet-b'}) == (NIC, 'b')
    assert resolve_ip('10.0.0.4', backends, {'vnet-x'}) is None
    assert resolve_ip(None, backends, set()) is None


def _gateway(rules):
    return {'id': 'agw', 'public': True, 'subnets': ['vnet/subnets/agw'], 'prefixes': AGW_SUBNET, 'rules': rules}


def _route(public=True, ipconfigs=('ipc-web',), ips=()):
    return {
        'frontend_public': public, 'listener_protocol': 'Https', 'listener_port': 443, 'backend_protocol': 'Http',
        'backend_port': 8080, 'backend_pool_id': 'pool', 'backend_ip_configuration_ids': list(ipconfigs),
        'backend_ip_addresses': list(ips),
    }


def test_app_gateway_listener_and_backend_port():
    results = {NIC: {'web': Reach(), 'by-ip': Reach(), 'denied': Reach()}}
    nsg_rules = {
        'nsg-web': [_rule(100, access='Deny', ports='*', protocol='*')],  # direct internet closed
        'nsg-denied': [_rule(100, access='Deny', source='10.0.50.0/24', ports='8080')],
    }
    nics = [
        ('web', '10.0.1.4', 'vnet/subnets/app', ['nsg-web']),
        ('by-ip', '10.0.2.20', 'vnet/subnets/app', []),
        ('denied', '10.0.1.5', 'vnet/subnets/app', ['nsg-denied']),
    ]
    ipconfigs = {'ipc-web': (NIC, 'web'), 'ipc-denied': (NIC, 'denied')}
    backends = _backends(results, nics, ipconfigs, nsg_rules)
    rules = [_route(ipconfigs=('ipc-web', 'ipc-denied'), ips=('10.0.2.20',)), _route(public=False, ipconfigs=())]

    gw = app_gateways([_gateway(rules)], backends)['agw']

    assert (gw.public_reasons, gw.ports.to_strings(), gw.via) == (
        {'public_frontend'}, ['tcp:443-443'], {'public_listener'},
    )
    assert (results[NIC]['web'].ports.to_strings(), results[NIC]['web'].via) == (['tcp:8080-8080'], {'appgw:agw'})
    assert results[NIC]['by-ip'].ports.to_strings() == ['tcp:8080-8080']
    assert results[NIC]['denied'].ports.is_empty()


def test_app_gateway_subnet_nsg_closes_listener_and_backends():
    results = {NIC: {'web': Reach()}}
    nsg_rules = {'nsg-agw': [_rule(100, ports='80')]}  # listener 443 not admitted
    subnets = {'vnet/subnets/agw': SubnetFacts(['nsg-agw'], [])}
    nics = [('web', '10.0.1.4', 'vnet/subnets/app', [])]
    backends = _backends(results, nics, {'ipc-web': (NIC, 'web')}, nsg_rules, subnets)

    gw = app_gateways([_gateway([_route()])], backends)['agw']

    assert gw.ports.is_empty()
    assert results[NIC]['web'].ports.is_empty()


def _dnat(sources=('*',), translated='10.0.3.30', port='2222', translated_port='22'):
    return {
        'source_addresses': list(sources), 'destination_addresses': ['20.8.8.8'], 'destination_ports': [port],
        'protocols': ['TCP'], 'translated_address': translated, 'translated_port': translated_port,
    }


def _firewall(rules):
    return {
        'id': 'fw', 'public': True, 'public_ips': ['20.8.8.8'], 'subnets': ['vnet/subnets/azurefirewallsubnet'],
        'prefixes': ['10.0.60.0/26'], 'rules': rules,
    }


def test_firewall_dnat_world_vs_restricted_source():
    results = {NIC: {'ssh': Reach(), 'rdp': Reach()}}
    backends = _backends(
        results, [
            ('ssh', '10.0.3.30', 'vnet/subnets/app', []),
            ('rdp', '10.0.3.31', 'vnet/subnets/app', []),
        ],
    )
    restricted = _dnat(sources=('203.0.113.0/24',), translated='10.0.3.31', port='3389', translated_port='3389')

    fw = firewalls([_firewall([_dnat(), restricted])], backends)['fw']

    assert (fw.public_reasons, fw.ports.to_strings(), fw.via) == ({'public_ip'}, ['tcp:2222-2222'], {'dnat_rule'})
    assert (results[NIC]['ssh'].ports.to_strings(), results[NIC]['ssh'].via) == (
        ['tcp:22-22'], {'azure_firewall_dnat:fw'},
    )
    assert results[NIC]['rdp'].ports.is_empty()


def test_dnat_from_world_needs_this_firewalls_address():
    assert dnat_from_world(_dnat(), {'20.8.8.8'})
    assert not dnat_from_world(_dnat(), {'20.9.9.9'})  # policy rule aimed at a sibling firewall
    assert not dnat_from_world({**_dnat(), 'source_addresses': []}, {'20.8.8.8'})  # IP groups only


def test_dnat_unresolved_target_keeps_firewall_reachable():
    # On-premises or another subscription: the firewall still forwards (upper bound, like an LB).
    fw = firewalls([_firewall([_dnat(translated='192.168.10.4')])], _backends({NIC: {}}))['fw']
    assert fw.ports.to_strings() == ['tcp:2222-2222']


def test_ports_of():
    assert ports_of(['TCP', 'UDP'], ['53']).to_strings() == ['tcp:53-53', 'udp:53-53']
    assert ports_of(['Any'], ['8000-8001']).to_strings() == ['tcp:8000-8001', 'udp:8000-8001']
    assert ports_of(['ICMP'], ['*']).is_empty()
    assert ports_of(['TCP'], [None]).is_empty()
    assert ports_of(None, ['22']).is_empty()


def test_easy_auth_verdict():
    assert easy_auth({'auth_enabled': True, 'action': 'Return401'}) == ('required', ['easy_auth'])
    assert easy_auth({'auth_enabled': True, 'action': 'RedirectToLoginPage'})[0] == 'required'
    assert easy_auth({'auth_enabled': True, 'action': 'AllowAnonymous'}) == ('unknown', ['app_decides'])
    assert easy_auth({'auth_enabled': False, 'action': 'Return403'})[0] == 'unknown'
    assert easy_auth({'auth_enabled': None, 'action': None})[0] == 'unknown'  # unreadable: never required


def test_app_gateway_waf_is_a_reason_only():
    prevention = app_gateway({'waf_enabled': True, 'waf_mode': 'Prevention'})
    assert prevention == ('unknown', ['backend_decides', 'waf_prevention'])
    assert app_gateway({'waf_enabled': True, 'waf_mode': 'Detection'}) == ('unknown', ['backend_decides'])
    assert app_gateway({'waf_enabled': None, 'waf_mode': None}) == ('unknown', ['backend_decides'])
