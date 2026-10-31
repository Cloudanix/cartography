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
