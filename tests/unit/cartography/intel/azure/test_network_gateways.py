"""
Application Gateway / Azure Firewall transforms, fed real SDK models so the attribute names
match what as_legacy_dict returns for the installed azure-mgmt-network.
"""
from unittest.mock import MagicMock

from azure.core.exceptions import HttpResponseError
from azure.mgmt.network import models

from cartography.intel.azure import network_gateways
from cartography.intel.azure.util.sdk_models import as_legacy_dict

PARAMS = {'UPDATE_TAG': 1}
SUB = '00-00'
AGW = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/agw'
FW = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/azureFirewalls/fw'
POLICY = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/firewallPolicies/pol'
NIC_IPC = f'/subscriptions/{SUB}/resourceGroups/RG/providers/Microsoft.Network/networkInterfaces/web/ipConfigurations/i'


def _ref(name):
    return {'id': f'{AGW}/{name}'}


def _gateway():
    return models.ApplicationGateway({
        'id': AGW, 'name': 'agw', 'location': 'eastus',
        'properties': {
            'sku': {'name': 'WAF_v2', 'tier': 'WAF_v2'},
            'gatewayIPConfigurations': [{'id': f'{AGW}/gic', 'properties': {'subnet': {'id': '/sub/agw-subnet'}}}],
            'frontendIPConfigurations': [
                {'id': f'{AGW}/frontendIPConfigurations/public', 'properties': {'publicIPAddress': {'id': '/pip/agw'}}},
                {'id': f'{AGW}/frontendIPConfigurations/private', 'properties': {'privateIPAddress': '10.0.50.10'}},
            ],
            'frontendPorts': [
                {'id': f'{AGW}/frontendPorts/https', 'properties': {'port': 443}},
                {'id': f'{AGW}/frontendPorts/http', 'properties': {'port': 80}},
            ],
            'httpListeners': [
                {
                    'id': f'{AGW}/httpListeners/public', 'properties': {
                        'frontendIPConfiguration': _ref('frontendIPConfigurations/PUBLIC'),
                        'frontendPort': _ref('frontendPorts/https'), 'protocol': 'Https',
                    },
                },
                {
                    'id': f'{AGW}/httpListeners/internal', 'properties': {
                        'frontendIPConfiguration': _ref('frontendIPConfigurations/private'),
                        'frontendPort': _ref('frontendPorts/http'), 'protocol': 'Http',
                    },
                },
            ],
            'backendAddressPools': [{
                'id': f'{AGW}/backendAddressPools/web', 'properties': {
                    'backendIPConfigurations': [{'id': NIC_IPC}],
                    'backendAddresses': [{'ipAddress': '10.0.2.20'}, {'fqdn': 'app.azurewebsites.net'}],
                },
            }],
            'backendHttpSettingsCollection': [
                {'id': f'{AGW}/backendHttpSettingsCollection/s8080', 'properties': {'port': 8080, 'protocol': 'Http'}},
            ],
            'requestRoutingRules': [
                {
                    'id': f'{AGW}/requestRoutingRules/basic', 'name': 'basic', 'properties': {
                        'ruleType': 'Basic', 'httpListener': _ref('httpListeners/public'),
                        'backendAddressPool': _ref('backendAddressPools/web'),
                        'backendHttpSettings': _ref('backendHttpSettingsCollection/s8080'),
                    },
                },
                {
                    'id': f'{AGW}/requestRoutingRules/paths', 'name': 'paths', 'properties': {
                        'ruleType': 'PathBasedRouting', 'httpListener': _ref('httpListeners/internal'),
                        'urlPathMap': _ref('urlPathMaps/map'),
                    },
                },
                # Redirect only: no backend, no route.
                {
                    'id': f'{AGW}/requestRoutingRules/redirect', 'name': 'redirect', 'properties': {
                        'ruleType': 'Basic', 'httpListener': _ref('httpListeners/internal'),
                        'redirectConfiguration': _ref('redirectConfigurations/r'),
                    },
                },
            ],
            'urlPathMaps': [{
                'id': f'{AGW}/urlPathMaps/map', 'properties': {
                    'defaultBackendAddressPool': _ref('backendAddressPools/web'),
                    'defaultBackendHttpSettings': _ref('backendHttpSettingsCollection/s8080'),
                    'pathRules': [{
                        'id': f'{AGW}/urlPathMaps/map/pathRules/api', 'properties': {
                            'paths': ['/api/*'], 'backendAddressPool': _ref('backendAddressPools/web'),
                            'backendHttpSettings': _ref('backendHttpSettingsCollection/s8080'),
                        },
                    }],
                },
            }],
            'webApplicationFirewallConfiguration': {'enabled': True, 'firewallMode': 'Prevention'},
        },
    })


def test_application_gateway_transform():
    gw = network_gateways.transform_application_gateway(as_legacy_dict(_gateway()), PARAMS)

    waf = (gw['sku_tier'], gw['waf_enabled'], gw['waf_mode'], gw['waf_policy_id'])
    assert waf == ('WAF_v2', True, 'Prevention', None)
    assert gw['subnet_ids'] == ['/sub/agw-subnet']
    assert gw['public_ip_ids'] == ['/pip/agw']
    assert gw['backend_ip_configuration_ids'] == [NIC_IPC]
    routes = {r['id'].rsplit('/', 2)[-2] + '/' + r['id'].rsplit('/', 1)[-1]: r for r in gw['rules']}
    assert sorted(routes) == ['pathRules/api', 'requestRoutingRules/basic', 'requestRoutingRules/paths']
    basic = routes['requestRoutingRules/basic']
    assert basic == {
        'id': f'{AGW}/requestRoutingRules/basic', 'name': 'basic', 'frontend_public': True,
        'listener_protocol': 'Https', 'listener_port': 443, 'backend_protocol': 'Http', 'backend_port': 8080,
        'backend_pool_id': f'{AGW}/backendAddressPools/web'.lower(),
        'backend_ip_configuration_ids': [NIC_IPC.lower()],
        'backend_ip_addresses': ['10.0.2.20'], 'backend_fqdns': ['app.azurewebsites.net'],
    }
    # The path rule hangs off its routing rule (two rules may share one URL path map).
    assert routes['pathRules/api']['id'] == f'{AGW}/requestRoutingRules/paths/pathRules/api'
    assert routes['pathRules/api']['frontend_public'] is False
    assert routes['pathRules/api']['listener_port'] == 80


def _firewall(**properties):
    return models.AzureFirewall({
        'id': FW, 'name': 'fw', 'location': 'eastus',
        'properties': {
            'sku': {'name': 'AZFW_VNet', 'tier': 'Standard'},
            'ipConfigurations': [{
                'id': f'{FW}/ipc', 'name': 'ipc', 'properties': {
                    'privateIPAddress': '10.0.60.4', 'subnet': {'id': '/sub/AzureFirewallSubnet'},
                    'publicIPAddress': {'id': '/pip/fw'},
                },
            }],
            **properties,
        },
    })


def _nat(name, sources, port='2222', translated='10.0.3.30', translated_port='22'):
    return {
        'name': name, 'sourceAddresses': sources, 'destinationAddresses': ['20.8.8.8'],
        'destinationPorts': [port], 'protocols': ['TCP'], 'translatedAddress': translated,
        'translatedPort': translated_port,
    }


def test_firewall_classic_dnat_rules():
    firewall = _firewall(
        natRuleCollections=[
            {
                'id': f'{FW}/natRuleCollections/in', 'name': 'in', 'properties': {
                    'priority': 100, 'action': {'type': 'Dnat'}, 'rules': [_nat('ssh', ['*'])],
                },
            },
            {
                'id': f'{FW}/natRuleCollections/out', 'name': 'out', 'properties': {
                    'priority': 200, 'action': {'type': 'Snat'}, 'rules': [_nat('snat', ['*'])],
                },
            },
        ],
    )
    fw = network_gateways.transform_firewall(as_legacy_dict(firewall), PARAMS)

    assert (fw['private_ip_addresses'], fw['subnet_ids'], fw['public_ip_ids']) == (
        ['10.0.60.4'], ['/sub/AzureFirewallSubnet'], ['/pip/fw'],
    )
    assert fw['rules'] == [{
        'id': f'{FW}/natRuleCollections/in/rules/ssh', 'name': 'ssh', 'protocols': ['TCP'],
        'source_addresses': ['*'], 'source_ip_groups': [], 'destination_addresses': ['20.8.8.8'],
        'destination_ports': ['2222'], 'translated_address': '10.0.3.30', 'translated_fqdn': None,
        'translated_port': '22',
    }]


def _group():
    return models.FirewallPolicyRuleCollectionGroup({
        'id': f'{POLICY}/ruleCollectionGroups/g', 'name': 'g',
        'properties': {
            'priority': 100, 'ruleCollections': [
                {
                    'ruleCollectionType': 'FirewallPolicyNatRuleCollection', 'name': 'dnat', 'priority': 100,
                    'action': {'type': 'DNAT'},
                    'rules': [{
                        'ruleType': 'NatRule', 'name': 'web', 'ipProtocols': ['TCP'], 'sourceAddresses': ['*'],
                        'destinationAddresses': ['20.8.8.8'], 'destinationPorts': ['443'],
                        'translatedAddress': '10.0.3.31', 'translatedPort': '8443',
                    }],
                },
                {
                    'ruleCollectionType': 'FirewallPolicyFilterRuleCollection', 'name': 'allow', 'priority': 200,
                    'action': {'type': 'Allow'}, 'rules': [],
                },
            ],
        },
    })


def test_firewall_policy_dnat_rules_are_merged():
    client = MagicMock()
    client.azure_firewalls.list_all.return_value = [
        _firewall(firewallPolicy={'id': POLICY}),
        _firewall(firewallPolicy={'id': POLICY.replace(SUB, 'other-sub')}),
    ]
    client.firewall_policy_rule_collection_groups.list.return_value = [_group()]

    same, other = network_gateways.get_firewalls(client, SUB, None, PARAMS)

    client.firewall_policy_rule_collection_groups.list.assert_called_once_with('rg', 'pol')
    assert [(r['id'], r['protocols'], r['translated_port']) for r in same['rules']] == [
        (f'{POLICY}/ruleCollectionGroups/g/ruleCollections/dnat/rules/web', ['TCP'], '8443'),
    ]
    # A policy in another subscription is skipped, not read through the wrong client.
    assert other['rules'] == []


def test_list_errors_yield_nothing():
    client = MagicMock()
    client.application_gateways.list_all.side_effect = HttpResponseError('forbidden')
    client.azure_firewalls.list_all.side_effect = HttpResponseError('forbidden')
    assert network_gateways.get_application_gateways(client, None, PARAMS) == []
    assert network_gateways.get_firewalls(client, SUB, None, PARAMS) == []
