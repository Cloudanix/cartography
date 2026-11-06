"""
as_legacy_dict against real Azure SDK models built from REST payloads, the way
the SDK deserializes an ARM response. Asserts the exact keys the ingestion code
reads (the TypeSpec models' own as_dict() nests them under 'properties').
"""
from azure.mgmt.compute import models as compute_models
from azure.mgmt.containerservice import models as aks_models
from azure.mgmt.cosmosdb import models as cosmos_models
from azure.mgmt.keyvault import models as kv_models
from azure.mgmt.network import models as net_models
from azure.mgmt.sql import models as sql_models
from azure.mgmt.storage import models as storage_models
from azure.mgmt.web import models as web_models

from cartography.intel.azure.util.sdk_models import as_legacy_dict

SUB = '/subscriptions/00-00/resourceGroups/rg/providers'
NSG_ID = f'{SUB}/Microsoft.Network/networkSecurityGroups/nsg1'


def test_nsg_rules_are_flattened():
    nsg = net_models.NetworkSecurityGroup({
        'id': NSG_ID, 'name': 'nsg1', 'location': 'eastus',
        'properties': {
            'securityRules': [{
                'id': f'{NSG_ID}/securityRules/ssh', 'name': 'ssh',
                'properties': {
                    'protocol': 'Tcp', 'access': 'Allow', 'direction': 'Inbound', 'priority': 100,
                    'sourceAddressPrefix': '*', 'sourceAddressPrefixes': [],
                    'sourcePortRange': '*', 'destinationPortRange': '22',
                    'destinationPortRanges': ['80', '443'], 'destinationAddressPrefix': '*',
                },
            }],
        },
    })

    assert nsg.as_dict()['properties']['securityRules'][0]['properties']['protocol'] == 'Tcp'
    rule = as_legacy_dict(nsg)['security_rules'][0]
    assert rule['id'] == f'{NSG_ID}/securityRules/ssh'
    assert rule['protocol'] == 'Tcp'
    assert rule['access'] == 'Allow'
    assert rule['direction'] == 'Inbound'
    assert rule['priority'] == 100
    assert rule['source_address_prefix'] == '*'
    assert rule['source_port_range'] == '*'
    assert rule['destination_port_range'] == '22'
    assert rule['destination_port_ranges'] == ['80', '443']
    assert rule['destination_address_prefix'] == '*'


def test_subnet_nic_and_public_ip_are_flattened():
    subnet = as_legacy_dict(
        net_models.Subnet({
            'id': f'{SUB}/Microsoft.Network/virtualNetworks/v/subnets/s', 'name': 's',
            'properties': {'addressPrefix': '10.0.0.0/24', 'networkSecurityGroup': {'id': NSG_ID}},
        }),
    )
    assert subnet['network_security_group'] == {'id': NSG_ID}
    assert subnet['address_prefix'] == '10.0.0.0/24'

    nic = as_legacy_dict(
        net_models.NetworkInterface({
            'id': f'{SUB}/Microsoft.Network/networkInterfaces/n', 'name': 'n',
            'properties': {
                'networkSecurityGroup': {'id': NSG_ID},
                'ipConfigurations': [{
                    'id': 'ipc', 'name': 'ipc',
                    'properties': {
                        'privateIPAddress': '10.0.0.4',
                        'publicIPAddress': {'id': 'pip'},
                        'subnet': {'id': 'subnet'},
                    },
                }],
            },
        }),
    )
    assert nic['network_security_group'] == {'id': NSG_ID}
    conf = nic['ip_configurations'][0]
    assert conf['public_ip_address'] == {'id': 'pip'}
    assert conf['subnet'] == {'id': 'subnet'}
    assert conf['private_ip_address'] == '10.0.0.4'

    pip = as_legacy_dict(
        net_models.PublicIPAddress({
            'id': 'pip', 'name': 'pip', 'location': 'eastus',
            'properties': {'ipAddress': '20.1.2.3', 'publicIPAllocationMethod': 'Static'},
        }),
    )
    assert pip['ip_address'] == '20.1.2.3'
    assert pip['public_ip_allocation_method'] == 'Static'


def test_storage_account_network_rule_set():
    account = as_legacy_dict(
        storage_models.StorageAccount({
            'id': f'{SUB}/Microsoft.Storage/storageAccounts/sa', 'name': 'sa', 'location': 'eastus',
            'properties': {
                'networkAcls': {'defaultAction': 'Deny', 'bypass': 'AzureServices'},
                'allowBlobPublicAccess': True, 'publicNetworkAccess': 'Disabled',
            },
        }),
    )
    assert account['network_rule_set']['default_action'] == 'Deny'
    assert account['allow_blob_public_access'] is True
    assert account['public_network_access'] == 'Disabled'


def test_key_vault_keeps_properties_envelope():
    # Vault was never flattened: the legacy shape is vault['properties'][snake_case].
    vault = as_legacy_dict(
        kv_models.Vault({
            'id': f'{SUB}/Microsoft.KeyVault/vaults/kv', 'name': 'kv', 'location': 'eastus',
            'systemData': {'createdAt': '2026-01-01T00:00:00Z'},
            'properties': {
                'tenantId': '00000000-0000-0000-0000-000000000000', 'sku': {'family': 'A', 'name': 'standard'},
                'vaultUri': 'https://kv.vault.azure.net/', 'publicNetworkAccess': 'Enabled',
                'networkAcls': {'defaultAction': 'Deny'},
            },
        }),
    )
    assert vault['properties']['network_acls']['default_action'] == 'Deny'
    assert vault['properties']['vault_uri'] == 'https://kv.vault.azure.net/'
    assert vault['properties']['public_network_access'] == 'Enabled'
    assert vault['system_data']['created_at'] == '2026-01-01T00:00:00Z'


def test_sql_server_msrest_model():
    server = as_legacy_dict(
        sql_models.Server.deserialize({
            'id': f'{SUB}/Microsoft.Sql/servers/s', 'name': 's', 'location': 'eastus',
            'properties': {'publicNetworkAccess': 'Enabled', 'fullyQualifiedDomainName': 's.database.windows.net'},
        }),
    )
    assert server['public_network_access'] == 'Enabled'
    assert server['fully_qualified_domain_name'] == 's.database.windows.net'


def test_web_aks_cosmos_and_vm():
    site = as_legacy_dict(
        web_models.Site({
            'id': f'{SUB}/Microsoft.Web/sites/app', 'name': 'app', 'location': 'eastus',
            'properties': {'hostNamesDisabled': False},
        }),
    )
    assert site['host_names_disabled'] is False

    conf = as_legacy_dict(
        web_models.SiteConfigResource({
            'id': f'{SUB}/Microsoft.Web/sites/app/config/web', 'properties': {'publicNetworkAccess': 'Enabled'},
        }),
    )
    assert conf['public_network_access'] == 'Enabled'

    aks = as_legacy_dict(
        aks_models.ManagedCluster({
            'id': f'{SUB}/Microsoft.ContainerService/managedClusters/c', 'name': 'c', 'location': 'eastus',
            'properties': {'publicNetworkAccess': 'Enabled'},
        }),
    )
    assert aks['public_network_access'] == 'Enabled'

    cosmos = as_legacy_dict(
        cosmos_models.DatabaseAccountGetResults({
            'id': f'{SUB}/Microsoft.DocumentDB/databaseAccounts/db', 'name': 'db', 'location': 'eastus',
            'properties': {'publicNetworkAccess': 'Enabled', 'ipRules': [{'ipAddressOrRange': '20.1.2.3'}]},
        }),
    )
    assert cosmos['public_network_access'] == 'Enabled'
    assert cosmos['ip_rules'] == [{'ip_address_or_range': '20.1.2.3'}]

    vm = as_legacy_dict(
        compute_models.VirtualMachine({
            'id': f'{SUB}/Microsoft.Compute/virtualMachines/vm', 'name': 'vm', 'location': 'eastus',
            'properties': {
                'networkProfile': {'networkInterfaces': [{'id': 'nic1'}]},
                'storageProfile': {'osDisk': {'osType': 'Linux', 'name': 'd', 'createOption': 'FromImage'}},
            },
        }),
    )
    assert vm['network_profile']['network_interfaces'] == [{'id': 'nic1'}]
    assert vm['storage_profile']['os_disk']['os_type'] == 'Linux'
