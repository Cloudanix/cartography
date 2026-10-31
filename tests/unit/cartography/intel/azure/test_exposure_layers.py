from cartography.intel.azure.compute import _vmss_front_doors
from cartography.intel.azure.exposure_layers.access import flag_auth
from cartography.intel.azure.exposure_layers.access import required_by
from cartography.intel.azure.exposure_layers.blast_radius import cosmos_via
from cartography.intel.azure.exposure_layers.blast_radius import sql_via
from cartography.intel.azure.exposure_layers.network import blind_hops
from cartography.intel.azure.exposure_layers.network import for_sku
from cartography.intel.azure.exposure_layers.network import gate
from cartography.intel.azure.exposure_layers.network import nsg_open
from cartography.intel.azure.exposure_layers.network import parse_port_range
from cartography.intel.azure.exposure_layers.network import rule_ports
from cartography.intel.azure.exposure_layers.network import SubnetFacts
from cartography.intel.azure.exposure_layers.reach import backend_ports
from cartography.intel.azure.exposure_layers.reach import cosmos_accounts
from cartography.intel.azure.exposure_layers.reach import frontend_ports
from cartography.intel.azure.exposure_layers.reach import sql_servers
from cartography.intel.azure.exposure_layers.software import function_runtime
from cartography.intel.azure.exposure_layers.software import sql_engine
from cartography.intel.azure.network import _load_balancer_rules
from cartography.intel.azure.sql import _azure_ad_only
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
    disabled = sql_servers([{**base, 'pna': 'Disabled', 'rules': [{'address_count': None}]}])['s']
    assert (office.public_reasons, office.ports.is_empty()) == ({'public_endpoint'}, True)
    assert world.ports.to_strings() == ['tcp:1433-1433']
    assert unread_pg.ports.to_strings() == ['tcp:5432-5432']
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
    sql = {'ranges': [['0.0.0.0', '0.0.0.0'], ['20.1.1.0', '20.1.1.255']]}
    assert sql_via(['20.1.1.7'], sql, public=True) == 'firewall_ip_rule'
    assert sql_via(['30.0.0.1'], sql, public=False) == 'azure_services_rule'
    assert sql_via([], {'ranges': []}, public=True) == 'public_endpoint'
    assert sql_via([], {'ranges': []}, public=False) is None
    cosmos = {'cidrs': ['40.0.0.0/24'], 'azure_services': False}
    assert cosmos_via(['40.0.0.9'], cosmos, public=False) == 'firewall_ip_rule'
    assert cosmos_via(['41.0.0.9'], cosmos, public=False) is None
