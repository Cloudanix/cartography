"""
Network fetchers fed real SDK models (built from ARM payloads): the fields the
exposure jobs depend on must arrive in the flattened shape the loaders read.
"""
from unittest.mock import MagicMock

from azure.mgmt.network import models

from cartography.intel.azure import network

PARAMS = {'UPDATE_TAG': 1}
RG = '/subscriptions/00-00/resourceGroups/rg/providers/Microsoft.Network'
NSG_ID = f'{RG}/networkSecurityGroups/nsg1'
SUBNET_ID = f'{RG}/virtualNetworks/vnet1/subnets/s1'
PIP_ID = f'{RG}/publicIPAddresses/pip1'


def _nsg() -> models.NetworkSecurityGroup:
    return models.NetworkSecurityGroup({
        'id': NSG_ID, 'name': 'nsg1', 'location': 'eastus',
        'properties': {
            'securityRules': [{
                'id': f'{NSG_ID}/securityRules/web', 'name': 'web',
                'properties': {
                    'protocol': 'Tcp', 'access': 'Allow', 'direction': 'Inbound', 'priority': 100,
                    'sourceAddressPrefix': 'Internet', 'sourcePortRange': '*',
                    'destinationPortRanges': ['80', '443'], 'destinationAddressPrefix': '*',
                },
            }],
        },
    })


def test_nsg_rules_arrive_with_their_properties():
    client = MagicMock()
    client.network_security_groups.list_all.return_value = [_nsg()]

    groups = network.get_network_security_groups_list(client, None, PARAMS)
    rules = network.get_network_security_rules_list(groups, client, PARAMS)

    assert len(rules) == 1
    rule = rules[0]
    assert rule['security_group_id'] == NSG_ID
    assert rule['protocol'] == 'Tcp'
    assert rule['access'] == 'Allow'
    assert rule['direction'] == 'Inbound'
    assert rule['source_address_prefix'] == 'Internet'
    assert rule['destination_port_ranges'] == ['80', '443']


def test_subnet_keeps_its_nsg_link():
    client = MagicMock()
    client.subnets.list.return_value = [
        models.Subnet({
            'id': SUBNET_ID, 'name': 's1',
            'properties': {'addressPrefix': '10.0.0.0/24', 'networkSecurityGroup': {'id': NSG_ID}},
        }),
    ]
    vnets = [{'resource_group': 'rg', 'name': 'vnet1', 'location': 'eastus'}]

    subnets = network.get_networks_subnets_list(vnets, client, PARAMS)

    assert subnets[0]['network_security_group_id'] == NSG_ID


def test_nic_keeps_public_ip_subnet_and_nsg_links():
    client = MagicMock()
    client.network_interfaces.list_all.return_value = [
        models.NetworkInterface({
            'id': f'{RG}/networkInterfaces/nic1', 'name': 'nic1', 'location': 'eastus',
            'properties': {
                'networkSecurityGroup': {'id': NSG_ID},
                'ipConfigurations': [{
                    'id': f'{RG}/networkInterfaces/nic1/ipConfigurations/ipc', 'name': 'ipc',
                    'properties': {'publicIPAddress': {'id': PIP_ID}, 'subnet': {'id': SUBNET_ID}},
                }],
            },
        }),
    ]

    nic = network.get_network_interfaces_list(client, None, PARAMS)[0]

    assert nic['public_ip_address'] == [{'public_ip_id': PIP_ID}]
    assert nic['subnet'] == [{'subnet_id': SUBNET_ID}]
    assert nic['network_security_group']['id'] == NSG_ID


def test_public_ip_keeps_its_address():
    client = MagicMock()
    client.public_ip_addresses.list_all.return_value = [
        models.PublicIPAddress({
            'id': PIP_ID, 'name': 'pip1', 'location': 'eastus',
            'properties': {'ipAddress': '20.1.2.3', 'publicIPAllocationMethod': 'Static'},
        }),
    ]

    ip = network.get_public_ip_addresses_list(client, None, PARAMS)[0]

    assert ip['ip_address'] == '20.1.2.3'
    assert ip['is_static_ip'] is True


def test_load_balancer_records_inbound_backend_pools():
    lb_id = f'{RG}/loadBalancers/lb1'
    client = MagicMock()
    client.load_balancers.list_all.return_value = [
        models.LoadBalancer({
            'id': lb_id, 'name': 'lb1', 'location': 'eastus',
            'properties': {
                'backendAddressPools': [{'id': f'{lb_id}/backendAddressPools/{p}'} for p in ('web', 'nat', 'egress')],
                'loadBalancingRules': [{
                    'id': f'{lb_id}/loadBalancingRules/http',
                    'properties': {'backendAddressPool': {'id': f'{lb_id.upper()}/backendAddressPools/WEB'}},
                }],
                'inboundNatRules': [{
                    'id': f'{lb_id}/inboundNatRules/ssh',
                    'properties': {'backendAddressPool': {'id': f'{lb_id}/backendAddressPools/nat'}},
                }],
                'outboundRules': [{
                    'id': f'{lb_id}/outboundRules/snat',
                    'properties': {'backendAddressPool': {'id': f'{lb_id}/backendAddressPools/egress'}},
                }],
            },
        }),
    ]

    [lb] = network.get_load_balancers_list(client, None, PARAMS)

    # Outbound (SNAT-only) pools receive no inbound traffic; ids are compared lowercased.
    assert lb['inbound_backend_pool_ids'] == [
        f'{lb_id}/backendAddressPools/nat'.lower(), f'{lb_id}/backendAddressPools/web'.lower(),
    ]
