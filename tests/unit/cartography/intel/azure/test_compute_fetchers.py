"""
VM fetcher fed a real SDK model: the network interfaces (VM -> NIC edge, which
every VM exposure statement walks) and OS profile must arrive.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock
from unittest.mock import patch

from azure.mgmt.compute import models

from cartography.intel.azure import compute

PARAMS = {'UPDATE_TAG': 1}
RG = '/subscriptions/00-00/resourceGroups/rg/providers'
NIC_ID = f'{RG}/Microsoft.Network/networkInterfaces/nic1'


def test_vm_network_interfaces_arrive():
    client = MagicMock()
    client.virtual_machines.list_all.return_value = [
        models.VirtualMachine({
            'id': f'{RG}/Microsoft.Compute/virtualMachines/vm1', 'name': 'vm1', 'location': 'eastus',
            'properties': {
                'networkProfile': {'networkInterfaces': [{'id': NIC_ID}]},
                'storageProfile': {'osDisk': {'osType': 'Linux', 'name': 'disk1', 'createOption': 'FromImage'}},
            },
        }),
    ]
    client.virtual_machines.instance_view.return_value = SimpleNamespace(
        statuses=[SimpleNamespace(code='PowerState/running')],
    )

    with patch.object(compute, 'get_client', return_value=client):
        [vm] = compute.get_vm_list(MagicMock(), '00-00', None, PARAMS)

    assert [nic['id'] for nic in vm['network_interfaces']] == [NIC_ID]
    assert vm['os_type'] == 'Linux'
    assert vm['os_disk_name'] == 'disk1'
    assert vm['power_state'] == 'running'


def _scale_set(name, ip_configuration):
    return models.VirtualMachineScaleSet({
        'id': f'{RG}/Microsoft.Compute/virtualMachineScaleSets/{name}', 'name': name, 'location': 'eastus',
        'properties': {
            'virtualMachineProfile': {
                'networkProfile': {
                    'networkInterfaceConfigurations': [{
                        'name': 'nic', 'properties': {
                            'primary': True, 'ipConfigurations': [{
                                'name': 'ip', 'properties': ip_configuration,
                            }],
                        },
                    }],
                },
            },
        },
    })


def test_vmss_front_doors_arrive():
    lb = f'{RG}/Microsoft.Network/loadBalancers/LB1'
    client = MagicMock()
    client.virtual_machine_scale_sets.list_all.return_value = [
        _scale_set('pip', {'publicIPAddressConfiguration': {'name': 'pub', 'properties': {}}}),
        _scale_set(
            'pooled', {
                'loadBalancerBackendAddressPools': [{'id': f'{lb}/backendAddressPools/web'}],
                'loadBalancerInboundNatPools': [{'id': f'{lb}/inboundNatPools/ssh'}],
            },
        ),
        models.VirtualMachineScaleSet({
            'id': f'{RG}/Microsoft.Compute/virtualMachineScaleSets/bare', 'name': 'bare', 'location': 'eastus',
        }),
    ]

    with patch.object(compute, 'get_client', return_value=client):
        sets = {s['name']: s for s in compute.get_vm_scale_sets_list(MagicMock(), '00-00', None, PARAMS)}

    assert {
        name: (s['public_ip_per_instance'], s['lb_backend_pool_ids'], s['lb_inbound_nat_lb_ids'])
        for name, s in sets.items()
    } == {
        'pip': (True, [], []),
        'pooled': (False, [f'{lb}/backendAddressPools/web'.lower()], [lb.lower()]),
        'bare': (False, [], []),
    }
