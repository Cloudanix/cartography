# Mock data for Virtual Networks
# Structure matches Azure SDK's .as_dict() output (flattened, not nested under "properties")
MOCK_VNETS = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/virtualNetworks/my-test-vnet",
        "name": "my-test-vnet",
        "location": "eastus",
        "properties": {
            "provisioning_state": "Succeeded",
        },
        "tags": {"env": "prod", "service": "vnet"},
    },
]

# Mock data for Network Security Groups
MOCK_NSGS = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkSecurityGroups/my-test-nsg",
        "name": "my-test-nsg",
        "location": "eastus",
        "tags": {"env": "prod", "service": "nsg"},
        "security_rules": [
            {
                "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkSecurityGroups/my-test-nsg/securityRules/allow-ssh-from-internet",
                "name": "allow-ssh-from-internet",
                "description": "Allow SSH from the internet",
                "protocol": "Tcp",
                "direction": "Inbound",
                "access": "Allow",
                "priority": 100,
                "source_port_range": "*",
                "destination_port_range": "22",
                "source_address_prefix": "*",
                "destination_address_prefix": "*",
            },
            {
                "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkSecurityGroups/my-test-nsg/securityRules/deny-rdp",
                "name": "deny-rdp",
                "properties": {
                    "protocol": "Tcp",
                    "direction": "Inbound",
                    "access": "Deny",
                    "priority": 200,
                    "source_port_range": "*",
                    "destination_port_ranges": ["3389"],
                    "source_address_prefix": "Internet",
                    "destination_address_prefix": "*",
                },
            },
        ],
        "default_security_rules": [
            {
                "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkSecurityGroups/my-test-nsg/defaultSecurityRules/AllowVnetInBound",
                "name": "AllowVnetInBound",
                "protocol": "*",
                "direction": "Inbound",
                "access": "Allow",
                "priority": 65000,
                "source_port_range": "*",
                "destination_port_range": "*",
                "source_address_prefix": "VirtualNetwork",
                "destination_address_prefix": "VirtualNetwork",
            },
        ],
    },
]

# Mock data for Subnets
# Structure matches Azure SDK's .as_dict() output (flattened, not nested under "properties")
MOCK_SUBNETS = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/virtualNetworks/my-test-vnet/subnets/subnet-with-nsg",
        "name": "subnet-with-nsg",
        "address_prefix": "10.0.1.0/24",
        "network_security_group": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkSecurityGroups/my-test-nsg",
        },
    },
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/virtualNetworks/my-test-vnet/subnets/subnet-without-nsg",
        "name": "subnet-without-nsg",
        "address_prefix": "10.0.2.0/24",
        "network_security_group": None,
    },
]


# Mock data for Public IP Addresses
# This fixture includes both shapes that Azure SDK's .as_dict() may return:
# - flattened fields at the top level
# - fields nested under "properties"
MOCK_PUBLIC_IPS = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/publicIPAddresses/my-public-ip-1",
        "name": "my-public-ip-1",
        "location": "eastus",
        "ip_address": "20.10.30.40",
        "public_ip_allocation_method": "Static",
    },
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/publicIPAddresses/my-public-ip-2",
        "name": "my-public-ip-2",
        "location": "eastus",
        "ip_address": "20.10.30.41",
        "public_ip_allocation_method": "Dynamic",
    },
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/publicIPAddresses/my-public-ip-3",
        "name": "my-public-ip-3",
        "location": "eastus",
        "properties": {
            "ip_address": "20.10.30.42",
            "public_ip_allocation_method": "Static",
        },
    },
]


# Mock data for Network Interfaces
# Structure matches Azure SDK's .as_dict() output (flattened, not nested under "properties")
MOCK_NETWORK_INTERFACES = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkInterfaces/my-nic-1",
        "name": "my-nic-1",
        "location": "eastus",
        "mac_address": "00-0D-3A-1B-C7-21",
        "virtual_machine": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Compute/virtualMachines/my-vm-1",
        },
        "network_security_group": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkSecurityGroups/my-test-nsg",
        },
        "ip_configurations": [
            {
                "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkInterfaces/my-nic-1/ipConfigurations/ipconfig1",
                "name": "ipconfig1",
                "private_ip_address": "10.0.1.4",
                "subnet": {
                    "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/virtualNetworks/my-test-vnet/subnets/subnet-with-nsg",
                },
                "public_ip_address": {
                    "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/publicIPAddresses/my-public-ip-1",
                },
            },
        ],
    },
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkInterfaces/my-nic-2",
        "name": "my-nic-2",
        "location": "eastus",
        "mac_address": "00-0D-3A-1B-C7-22",
        "virtual_machine": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Compute/virtualMachines/my-vm-2",
        },
        "ip_configurations": [
            {
                "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkInterfaces/my-nic-2/ipConfigurations/ipconfig1",
                "name": "ipconfig1",
                "private_ip_address": "10.0.2.4",
                "subnet": {
                    "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/virtualNetworks/my-test-vnet/subnets/subnet-without-nsg",
                },
                # No public IP for this NIC
            },
        ],
    },
    {
        # NIC without a VM (e.g., unattached NIC)
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkInterfaces/my-nic-unattached",
        "name": "my-nic-unattached",
        "location": "eastus",
        "mac_address": None,
        "virtual_machine": None,
        "ip_configurations": [
            {
                "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/networkInterfaces/my-nic-unattached/ipConfigurations/ipconfig1",
                "name": "ipconfig1",
                "private_ip_address": "10.0.1.5",
                "subnet": {
                    "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/virtualNetworks/my-test-vnet/subnets/subnet-with-nsg",
                },
                "public_ip_address": {
                    "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/publicIPAddresses/my-public-ip-2",
                },
            },
        ],
    },
]


DESCRIBE_NETWORKROUTE = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            routeTables/TestRoutetable1/routes1",
        "type":
        "Microsoft.Network/routeTables/routes",
        "name":
        "route1",
        "etag":
        "hhd-fftt-fsc",
        "routetable_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            routeTables/TestRoutetable1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            routeTables/TestRoutetable2/routes2",
        "type":
        "Microsoft.Network/routeTables/routes",
        "name":
        "route2",
        "etag":
        "hhd-fftt-fsc",
        "address_prefix": '0.0.0.0/0',
        'next_hop_type': 'Internet',
        "routetable_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            routeTables/TestRoutetable2",
    },
]


DESCRIBE_NETWORKS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork1",
        "type": "Microsoft.Network/virtualNetworks",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "TestNetwork1",
        "resource_guid": "assu-ttef-vdff",
        "provisioning_state": "Running",
        "enable_ddos_protection": True,
        "etag": "sewd-erd",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork2",
        "type": "Microsoft.Network/virtualNetworks",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "TestNetwork2",
        "resource_guid": "assu-ttef-vdff",
        "provisioning_state": "Running",
        "enable_ddos_protection": True,
        "etag": "sewd-erd",
    },
]


DESCRIBE_NETWORKSECURITYGROUPS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup1",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "Testgroup1",
        "etag": "sewd-erd",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2",
        "type": "Microsoft.Network/networkSecurityGroups",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "Testgroup2",
        "etag": "sewd-erd",
    },
]


DESCRIBE_NETWORKSECURITYRULES = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup1/securityRules/rule1",
        "type":
        "Microsoft.Network/networkSecurityGroups/securityRules",
        "name":
        "rule1",
        "etag":
        "hhd-fftt-fsc",
        "security_group_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup1",
        "access": "Allow",
        "source_port_range": "*",
        "protocol": "TCP",
        "source_address_prefix": "1.1.1.1/24",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2/securityRules/rule2",
        "type":
        "Microsoft.Network/networkSecurityGroups/securityRules",
        "name":
        "rule2",
        "etag":
        "hhd-fftt-fsc",
        "security_group_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2",
        "access": "Allow",
        "source_port_range": "8080",
        "protocol": "TCP",
        "source_address_prefix": "1.1.1.1/24",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2/securityRules/rule3",
        "type":
        "Microsoft.Network/networkSecurityGroups/securityRules",
        "name":
        "rule3",
        "etag":
        "hhd-fftt-fsc",
        "security_group_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2",
        "access": "Allow",
        "direction": "Inbound",
        "destination_port_range": "0-65535",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2/securityRules/rule4",
        "type":
        "Microsoft.Network/networkSecurityGroups/securityRules",
        "name":
        "rule4",
        "etag":
        "hhd-fftt-fsc",
        "security_group_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup1",
        "access": "Allow",
        "direction": "Inbound",
        "protocol": "ICMP",
        "source_address_prefix": "*",
    },
]


DESCRIBE_NETWORKINTERFACES = [
    {
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic",
        "name": "test-nic",
        "location": "eastus",
        "network_security_group": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup1",
        },
        "type": "Microsoft.Network/networkInterfaces",
    },
    {
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic1",
        "name": "test-nic1",
        "location": "eastus",
        "network_security_group": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2",
        },
        "type": "Microsoft.Network/networkInterfaces",
    },
    {
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic2",
        "name": "test-nic2",
        "location": "eastus",
        "network_security_group": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup1",
        },
        "type": "Microsoft.Network/networkInterfaces",
    },
    {
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic3",
        "name": "test-nic3",
        "location": "eastus",
        "network_security_group": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2",
        },
        "type": "Microsoft.Network/networkInterfaces",
    },
    {
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic4",
        "name": "test-nic4",
        "location": "eastus",
        "network_security_group": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup1",
        },
        "type": "Microsoft.Network/networkInterfaces",
    },
    {
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/networkInterfaces/test-nic5",
        "name": "test-nic5",
        "location": "eastus",
        "network_security_group": {
            "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2",
        },
        "type": "Microsoft.Network/networkInterfaces",
    },
]


DESCRIBE_NETWORKSUBNETS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork1/subnets/subnet1",
        "type":
        "Microsoft.Network/virtualNetworks/subnets",
        "resource_group":
        "TestRG",
        "name":
        "subnet1",
        "private_endpoint_network_policies":
        "ads-dgs.net",
        "private_link_service_network_policies":
        ".net",
        "etag":
        "hhd-fftt-fsc",
        "network_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork1",
        "network_security_group_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork2/subnets/subnet2",
        "type":
        "Microsoft.Network/virtualNetworks/subnets",
        "resource_group":
        "TestRG",
        "name":
        "subnet2",
        "private_endpoint_network_policies":
        "ads-dgs.net",
        "private_link_service_network_policies":
        ".net",
        "etag":
        "hhd-fftt-fsc",
        "network_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork2",
        "network_security_group_id":
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            networkSecurityGroups/Testgroup2",
    },
]


DESCRIBE_NETWORKUSAGES = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork1/subnets/subnet1",
        "unit": "unit",
        "currentValue": 1234,
        "limit": 9999,
        "network_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork2/subnets/subnet2",
        "unit": "unit",
        "currentValue": 1234,
        "limit": 9999,
        "network_id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork2",
    },
]


DESCRIBE_PUBLICIPADDRESSES = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            publicIPAddresses/ip1",
        "type": "Microsoft.Network/publicIPAddresses",
        "location": "West US",
        "name": "ip1",
        "etag": "sewd-erd",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            publicIPAddresses/ip2",
        "type": "Microsoft.Network/publicIPAddresses",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "ip2",
        "etag": "sewd-erd",
    },
]


DESCRIBE_PUBLICIPADDRESSES_REFERENCE = [
    {
        "public_ip_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            publicIPAddresses/ip1",
    },
    {
        "public_ip_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            publicIPAddresses/ip2",
    },
]


DESCRIBE_ROUTETABLE = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            routeTables/TestRoutetable1",
        "type": "Microsoft.Network/routeTables",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "TestRoutetable1",
        "etag": "sewd-erd",
        "subnets": [
            {
                "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork1/subnets/subnet1",
            },
        ],
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            routeTables/TestRoutetable2",
        "type": "Microsoft.Network/routeTables",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "TestRoutetable2",
        "etag": "sewd-erd",
        "subnets": [
            {
                "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.Network/\
            virtualNetworks/TestNetwork2/subnets/subnet2",
            },
        ],
    },
]

