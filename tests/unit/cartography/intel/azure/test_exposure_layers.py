import json

from cartography.intel.azure.compute import _vmss_front_doors
from cartography.intel.azure.exposure_layers.access import flag_auth
from cartography.intel.azure.exposure_layers.access import required_by
from cartography.intel.azure.exposure_layers.blast_radius import cosmos_via
from cartography.intel.azure.exposure_layers.blast_radius import reach_rows
from cartography.intel.azure.exposure_layers.blast_radius import sql_via
from cartography.intel.azure.exposure_layers.network import blind_hops
from cartography.intel.azure.exposure_layers.network import for_sku
from cartography.intel.azure.exposure_layers.network import gate
from cartography.intel.azure.exposure_layers.network import nsg_open
from cartography.intel.azure.exposure_layers.network import parse_port_range
from cartography.intel.azure.exposure_layers.network import rule_ports
from cartography.intel.azure.exposure_layers.network import SubnetFacts
from cartography.intel.azure.exposure_layers.network import world_denies
from cartography.intel.azure.exposure_layers.reach import attachments
from cartography.intel.azure.exposure_layers.reach import backend_ports
from cartography.intel.azure.exposure_layers.reach import BackendIndex
from cartography.intel.azure.exposure_layers.reach import cosmos_accounts
from cartography.intel.azure.exposure_layers.reach import frontend_ports
from cartography.intel.azure.exposure_layers.reach import lb_rule_text
from cartography.intel.azure.exposure_layers.reach import load_balancers
from cartography.intel.azure.exposure_layers.reach import merge
from cartography.intel.azure.exposure_layers.reach import network_acl_endpoints
from cartography.intel.azure.exposure_layers.reach import sql_servers
from cartography.intel.azure.exposure_layers.software import function_runtime
from cartography.intel.azure.exposure_layers.software import sql_engine
from cartography.intel.azure.network import _load_balancer_rules
from cartography.intel.azure.sql import _azure_ad_only
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.software import os_from_image_name


def _rule(priority, access='Allow', source='Internet', ports='*', protocol='Tcp', **extra):
    return {
        'direction': 'Inbound', 'access': access, 'priority': priority, 'protocol': protocol,
        'source_address_prefix': source, 'destination_port_range': ports, **extra,
    }


def test_parse_port_range():
    assert parse_port_range('80') == (80, 80)
    assert parse_port_range('1000-2000') == (1000, 2000)
    assert parse_port_range('*') == (0, 65535)
    assert parse_port_range('http') is None


def test_rule_ports_list_and_protocols():
    assert rule_ports({'protocol': 'Udp', 'destination_port_ranges': ['53', '500-501']}).to_strings() == [
        'udp:53-53', 'udp:500-501',
    ]
    assert rule_ports({'protocol': '*', 'destination_port_range': '22'}).to_strings() == ['tcp:22-22', 'udp:22-22']
    assert rule_ports({'protocol': 'Icmp', 'destination_port_range': '*'}).is_empty()


def test_nsg_first_match_by_priority_deny_wins():
    rules = [_rule(200, ports='*'), _rule(100, access='Deny', ports='22')]
    assert nsg_open(rules).to_strings() == ['tcp:0-21', 'tcp:23-65535']


def test_nsg_no_match_is_default_deny():
    # Only an RFC1918 source and an outbound rule: DenyAllInBound (65500) closes everything.
    rules = [_rule(100, source='10.0.0.0/8'), dict(_rule(110), direction='Outbound')]
    assert nsg_open(rules).is_empty()
    assert nsg_open([]).is_empty()


def test_nsg_ingested_default_rules_agree():
    defaults = [
        _rule(65000, source='VirtualNetwork', protocol='*'),
        _rule(65001, source='AzureLoadBalancer', protocol='*'),
        _rule(65500, access='Deny', source='*', protocol='*'),
    ]
    assert nsg_open(defaults).is_empty()
    assert nsg_open(defaults + [_rule(300, ports='443', source_address_prefixes=['1.2.3.4', '0.0.0.0/0'])]) == \
        PortSet.of('tcp', 443, 443)


def test_nsg_deny_for_one_destination_is_skipped():
    rules = [_rule(100, access='Deny', destination_address_prefix='10.0.0.4'), _rule(200, ports='443')]
    assert nsg_open(rules).to_strings() == ['tcp:443-443']


def test_standard_sku_closed_without_nsg():
    subnets = {'s': SubnetFacts([], [])}
    no_nsg = gate(['s'], [], subnets, {})
    assert for_sku(no_nsg, ['Standard']).ports.is_empty()
    assert for_sku(no_nsg, ['Basic']) == no_nsg
    assert for_sku(no_nsg, [None]) == no_nsg  # SKU not ingested: upper bound
    with_nsg = gate(['s'], ['nic-nsg'], subnets, {'nic-nsg': PortSet.of('tcp', 22, 22)})
    assert for_sku(with_nsg, ['Standard']).ports.to_strings() == ['tcp:22-22']


def test_two_level_gate_is_intersection():
    nsgs = {'subnet-nsg': PortSet.of('tcp', 443, 443), 'nic-nsg': PortSet.of('tcp', 0, 1000)}
    subnets = {'s1': SubnetFacts(['subnet-nsg'], []), 's2': SubnetFacts([], [])}
    assert gate(['s1'], ['nic-nsg'], subnets, nsgs).ports.to_strings() == ['tcp:443-443']
    # A level without an NSG allows everything.
    assert gate(['s2'], ['nic-nsg'], subnets, nsgs).ports.to_strings() == ['tcp:0-1000']
    assert gate(['s1'], [], subnets, nsgs).ports.to_strings() == ['tcp:443-443']


def test_blind_hops():
    assert blind_hops(['Internet', 'VirtualAppliance', None]) == ['unknown:udr_default_route_virtualappliance']


def test_lb_rule_ports():
    assert backend_ports({'protocol': 'Tcp', 'backend_port': 8080}).to_strings() == ['tcp:8080-8080']
    assert backend_ports({'protocol': 'All', 'backend_port': 0}) == PortSet.everything()
    assert frontend_ports({'protocol': 'Tcp', 'frontend_port_start': 50000, 'frontend_port_end': 50099}).to_strings() \
        == ['tcp:50000-50099']


def test_load_balancer_rules_flattened():
    lb = {
        'load_balancing_rules': [{
            'id': 'lb/rules/http', 'protocol': 'Tcp', 'frontend_port': 443, 'backend_port': 8080,
            'frontend_ip_configuration': {'id': 'LB/FE/public'}, 'backend_address_pool': {'id': 'LB/POOL/web'},
        }],
        'inbound_nat_rules': [{
            'id': 'lb/nat/ssh', 'protocol': 'Tcp', 'frontend_port': 50001, 'backend_port': 22,
            'frontend_ip_configuration': {'id': 'lb/fe/public'}, 'backend_ip_configuration': {'id': 'NIC/ipconfig1'},
        }],
        'inbound_nat_pools': [{
            'id': 'lb/pool/ssh', 'protocol': 'Tcp', 'frontend_port_range_start': 50000,
            'frontend_port_range_end': 50099, 'backend_port': 22, 'frontend_ip_configuration': {'id': 'lb/fe/public'},
        }],
    }
    http, nat, pool = _load_balancer_rules(lb)
    assert (http['kind'], http['frontend_ip_configuration_id'], http['backend_pool_ids']) == (
        'load_balancing', 'lb/fe/public', ['lb/pool/web'],
    )
    assert (nat['backend_ip_configuration_id'], nat['frontend_port_start'], nat['frontend_port_end']) == (
        'nic/ipconfig1', 50001, 50001,
    )
    assert (pool['kind'], pool['frontend_port_start'], pool['frontend_port_end']) == ('inbound_nat_pool', 50000, 50099)


def test_vmss_front_doors_subnets_and_nsgs():
    scale_set = {
        'virtual_machine_profile': {
            'network_profile': {
                'network_interface_configurations': [{
                    'network_security_group': {'id': 'NSG/A'},
                    'ip_configurations': [{'subnet': {'id': 'Subnet/1'}}],
                }],
            },
        },
    }
    doors = _vmss_front_doors(scale_set)
    assert (doors['subnet_ids'], doors['nsg_ids']) == (['subnet/1'], ['nsg/a'])


def test_sql_servers_world_threshold_and_unread_firewall():
    base = {'id': 's', 'pna': 'Enabled', 'vnet': False, 'engine': 'sqlserver', 'fetched': True, 'port': 1433}
    office = sql_servers([{**base, 'rules': [{'address_count': 256}]}])['s']
    world = sql_servers([{**base, 'rules': [{'address_count': 4294967296}]}])['s']
    unread_pg = sql_servers([{**base, 'engine': 'postgres', 'fetched': False, 'port': 5432, 'rules': []}])['s']
    unread_mssql = sql_servers([{**base, 'fetched': False, 'rules': []}])['s']
    disabled = sql_servers([{**base, 'pna': 'Disabled', 'rules': [{'address_count': None}]}])['s']
    assert (office.public_reasons, office.ports.is_empty()) == ({'public_endpoint'}, True)
    assert world.ports.to_strings() == ['tcp:1433-1433']
    assert unread_pg.ports.to_strings() == ['tcp:5432-5432']
    assert unread_mssql.ports.to_strings() == ['tcp:1433-1433']
    assert (disabled.public_reasons, disabled.ports.is_empty()) == (set(), True)


def test_cosmos_accounts_api_ports():
    base = {'id': 'c', 'pna': None, 'vnet_filter': False, 'rule_count': 0, 'ipranges': [], 'capabilities': []}
    mongo = cosmos_accounts([{**base, 'kind': 'MongoDB'}])['c']
    filtered = cosmos_accounts([{**base, 'kind': 'GlobalDocumentDB', 'rule_count': 1, 'ipranges': ['1.2.3.4']}])['c']
    assert mongo.ports.to_strings() == ['tcp:443-443', 'tcp:10255-10255']
    assert filtered.ports.is_empty()


def test_auth_verdicts():
    blob = flag_auth('anonymous_container_access', 'account_keys_or_entra_id')
    assert blob({'open': True}) == ('none', ['anonymous_container_access'])
    assert blob({'open': False})[0] == 'required'
    sql = required_by('entra_id_only', 'database_credentials')
    assert sql({'flag': True}) == ('required', ['entra_id_only'])
    assert sql({'flag': False}) == ('required', ['database_credentials'])


def test_azure_ad_only():
    assert _azure_ad_only({'administrators': {'azure_ad_only_authentication': True}}) is True
    assert _azure_ad_only({'auth_config': {'password_auth': 'Disabled'}}) is True
    assert _azure_ad_only({'administrators': None}) is False


def test_versions():
    assert os_from_image_name('0001-com-ubuntu-server-jammy', '22_04-lts-gen2') == 'ubuntu@22.04'
    assert os_from_image_name('WindowsServer', '2019-Datacenter') == 'windows-server@2019'
    assert function_runtime({'linux_fx': 'PYTHON|3.11'}) == 'python@3.11'
    assert function_runtime({'linux_fx': 'DOTNET-ISOLATED|8.0'}) == 'dotnet@8.0'
    assert function_runtime({'linux_fx': 'DOCKER|nginx:1.25'}) is None
    assert function_runtime({'linux_fx': '', 'node': '~18'}) == 'nodejs@18'
    assert sql_engine({'engine': 'postgres', 'version': '15'}) == 'postgres@15'
    assert sql_engine({'engine': 'sqlserver', 'version': '12.0'}) is None


def test_store_via_precedence():
    sql = {'ranges': [['0.0.0.0', '0.0.0.0', 'AllowAllWindowsAzureIps'], ['20.1.1.0', '20.1.1.255', 'office']]}
    assert sql_via(['20.1.1.7'], sql, public=True) == ('firewall_ip_rule', 'office')
    assert sql_via(['30.0.0.1'], sql, public=False) == ('azure_services_rule', 'azure_services_rule')
    assert sql_via([], {'ranges': []}, public=True) == ('public_endpoint', None)
    assert sql_via([], {'ranges': []}, public=False) is None
    cosmos = {'cidrs': ['40.0.0.0/24'], 'azure_services': False}
    assert cosmos_via(['40.0.0.9'], cosmos, public=False) == ('firewall_ip_rule', '40.0.0.0/24')
    assert cosmos_via(['41.0.0.9'], cosmos, public=False) is None


def test_reach_rows_carry_type_and_admitting_rule():
    vms = [{'id': 'vm-1', 'ips': ['20.1.1.7']}, {'id': 'vm-2', 'ips': []}]
    store = {'id': 'sql', 'port': 1433, 'ranges': [['20.1.1.0', '20.1.1.255', 'office']]}
    rows = reach_rows(vms, [store], sql_via, {}, lambda s: PortSet.of('tcp', 1433, 1433), 'AzureSQLServer')
    assert rows == [{
        'src': 'vm-1', 'dst': 'sql', 'dst_type': 'AzureSQLServer', 'ports': ['tcp:1433-1433'],
        'via': 'firewall_ip_rule', 'admitted_by': 'office',
    }]


def _nic_row(public=True, nsgs=(), subnets=('s',), skus=(None,)):
    pips = [{'id': 'pip-1', 'address': '20.1.2.3'}] if public else []
    return {
        'id': 'nic', 'public': public, 'pips': pips, 'skus': list(skus), 'subnets': list(subnets), 'nsgs': list(nsgs),
    }


def _attach(row, subnets, nsg_rules):
    nsgs = {i: nsg_open(r) for i, r in nsg_rules.items()}
    return attachments([row], 'NIC', 'public_ip', subnets, nsgs, world_denies(nsg_rules))[0]['nic']


def test_direct_path_hops_and_entry():
    subnets = {'s': SubnetFacts(['subnet-nsg'], [], route_table='rt')}
    rules = {'subnet-nsg': [_rule(100, ports='443')], 'nic-nsg': [_rule(100, ports='*')]}
    reach = _attach(_nic_row(nsgs=['nic-nsg']), subnets, rules)
    assert json.loads(reach.props()['exposure_paths']) == [{
        'via': 'direct_ipv4', 'ports': ['tcp:443-443'],
        'entry': {'type': 'public_ip', 'id': 'pip-1', 'address': '20.1.2.3'},
        'hops': [
            {'hop': 'public_ip', 'id': 'pip-1'}, {'hop': 'route', 'id': 'rt', 'rule': '0.0.0.0/0 -> Internet'},
            {'hop': 'nsg', 'id': 'subnet-nsg'}, {'hop': 'nsg', 'id': 'nic-nsg'},
        ],
    }]
    assert reach.props()['exposure_blocked_by'] == '[]'


def _blocked(reach):
    return json.loads(reach.props()['exposure_blocked_by'])


def test_blocked_by_nsg_deny_vs_not_allowed():
    subnets = {'s': SubnetFacts(['subnet-nsg'], [])}
    rules = {
        'subnet-nsg': [_rule(100, access='Deny', ports='*'), _rule(200, ports='*')],
        'nic-nsg': [_rule(100, source='10.0.0.0/8')],
        # Ingested default DenyAllInBound does not make a deny: not_allowed.
        'nic-default': [_rule(65500, access='Deny', source='*', protocol='*')],
    }
    denied = _blocked(_attach(_nic_row(nsgs=['nic-nsg']), subnets, rules))
    assert [(b['id'], b['reason'], b['detail']) for b in denied] == [
        ('subnet-nsg', 'denied', 'subnet_nsg'), ('nic-nsg', 'not_allowed', 'nic_nsg'),
    ]
    only_nic = _blocked(_attach(_nic_row(nsgs=['nic-default'], subnets=['other']), subnets, rules))
    assert [(b['hop'], b['id'], b['reason'], b['detail']) for b in only_nic] == [
        ('nsg', 'nic-default', 'not_allowed', 'nic_nsg'),
    ]


def test_blocked_by_disjoint_nsgs_blames_both():
    subnets = {'s': SubnetFacts(['subnet-nsg'], [])}
    rules = {'subnet-nsg': [_rule(100, ports='22')], 'nic-nsg': [_rule(100, ports='443')]}
    blocked = _blocked(_attach(_nic_row(nsgs=['nic-nsg']), subnets, rules))
    assert [b['id'] for b in blocked] == ['subnet-nsg', 'nic-nsg']


def test_blocked_by_standard_sku_and_udr():
    subnets = {'s': SubnetFacts([], []), 'nva': SubnetFacts([], ['unknown:udr_default_route_virtualappliance'], 'rt')}
    std = _blocked(_attach(_nic_row(skus=['Standard']), subnets, {}))
    assert std == [{
        'hop': 'nsg', 'id': None, 'reason': 'not_allowed', 'detail': 'standard_sku_closed_without_nsg',
        'ports': ['tcp:0-65535', 'udp:0-65535'],
    }]
    nva = _attach(_nic_row(subnets=['nva']), subnets, {})
    assert nva.via == {'unknown:udr_default_route_virtualappliance'}
    assert _blocked(nva) == [{
        'hop': 'route', 'id': 'rt', 'reason': 'unknown_next_hop',
        'detail': 'unknown:udr_default_route_virtualappliance',
    }]
    # Not public: nothing to explain.
    assert _blocked(_attach(_nic_row(public=False, skus=['Standard']), subnets, {})) == []


def _lb(rules, frontends=({'id': 'fe', 'pip': 'lb-pip'},)):
    return {'id': 'lb', 'sku': None, 'public_frontends': list(frontends), 'rules': rules}


def test_lb_paths_and_no_listener():
    lb_rule = {
        'id': 'lb/rules/https', 'kind': 'load_balancing', 'protocol': 'Tcp', 'frontend_port_start': 443,
        'frontend_port_end': 443, 'backend_port': 8443, 'frontend_ip_configuration_id': 'fe',
        'backend_pool_ids': ['pool'],
    }
    index = BackendIndex({'pool': [('NIC', 'nic')]}, {}, {})
    results = {'NIC': {'nic': Reach()}}
    gates = {('NIC', 'nic'): gate([], [], {}, {})}
    lb = load_balancers([_lb([lb_rule]), {**_lb([]), 'id': 'idle'}], index, gates, results)
    hops = [
        {'hop': 'public_ip', 'id': 'lb-pip'}, {'hop': 'listener', 'id': 'lb/rules/https', 'rule': 'tcp 443 -> 8443'},
    ]
    backend = json.loads(results['NIC']['nic'].props()['exposure_paths'])
    assert backend == [{
        'via': 'lb:lb', 'ports': ['tcp:8443-8443'], 'entry': {'type': 'load_balancer', 'id': 'lb'}, 'hops': hops,
    }]
    assert json.loads(lb['lb'].props()['exposure_paths'])[0]['ports'] == ['tcp:443-443']
    assert _blocked(lb['idle']) == [
        {'hop': 'listener', 'id': 'idle', 'reason': 'no_listener', 'detail': 'no_rule_on_public_frontend'},
    ]


def test_lb_rule_text():
    nat_pool = {'protocol': 'Tcp', 'frontend_port_start': 50000, 'frontend_port_end': 50099, 'backend_port': 22}
    assert lb_rule_text(nat_pool) == 'tcp 50000-50099 -> 22'
    assert lb_rule_text({'protocol': 'All', 'frontend_port_start': 0, 'backend_port': 0}) == 'all * -> *'


def test_vm_union_keeps_paths_and_blocks():
    nic = Reach(public_reasons={'public_ip'})
    nic.add_path(PortSet.of('tcp', 22, 22), 'direct_ipv4', [{'hop': 'public_ip', 'id': 'p'}], {'type': 'public_ip'})
    closed = Reach(public_reasons={'public_ip'})
    closed.block('nsg', 'g', 'denied')
    vm = Reach()
    merge(vm, nic)
    merge(vm, closed)
    assert json.loads(vm.props()['exposure_paths'])[0]['hops'] == [{'hop': 'public_ip', 'id': 'p'}]
    assert vm.blocked == [{'hop': 'nsg', 'id': 'g', 'reason': 'denied'}]


def test_paas_endpoint_path_and_blocker():
    base = {'pna': 'Enabled', 'http': False}
    out = network_acl_endpoints([
        {**base, 'id': 'open', 'default_action': 'Allow'}, {**base, 'id': 'shut', 'default_action': 'Deny'},
    ])
    assert json.loads(out['open'].props()['exposure_paths']) == [{
        'via': 'public_endpoint', 'ports': ['tcp:443-443'], 'entry': {'type': 'public_endpoint', 'id': 'open'},
        'hops': [{'hop': 'service', 'id': 'open'}],
    }]
    assert _blocked(out['shut']) == [{'hop': 'service', 'id': 'shut', 'reason': 'not_allowed'}]
