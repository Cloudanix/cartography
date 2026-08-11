MOCK_CLUSTERS = [
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/managedClusters/my-test-aks-cluster",
        "name": "my-test-aks-cluster",
        "location": "eastus",
        "properties": {
            "provisioning_state": "Succeeded",
            "kubernetes_version": "1.28.5",
            "fqdn": "my-test-aks-cluster-dns-abcdef.hcp.eastus.azmk8s.io",
            "api_server_access_profile": {"enable_private_cluster": False},
        },
        "tags": {"env": "prod", "service": "aks"},
    },
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/managedClusters/my-private-aks-cluster",
        "name": "my-private-aks-cluster",
        "location": "eastus",
        "properties": {
            "provisioning_state": "Succeeded",
            "kubernetes_version": "1.28.5",
            "fqdn": "my-private-aks-cluster-dns-abcdef.hcp.eastus.azmk8s.io",
            "api_server_access_profile": {"enable_private_cluster": True},
        },
        "tags": {"env": "prod", "service": "aks"},
    },
    # API Server VNet Integration: not a classic private cluster, but public
    # network access is disabled. The transform must still mark it as not
    # publicly reachable via the second gate.
    {
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/managedClusters/my-vnet-aks-cluster",
        "name": "my-vnet-aks-cluster",
        "location": "eastus",
        "properties": {
            "provisioning_state": "Succeeded",
            "kubernetes_version": "1.28.5",
            "fqdn": "my-vnet-aks-cluster-dns-abcdef.hcp.eastus.azmk8s.io",
            "api_server_access_profile": {"enable_private_cluster": False},
            "public_network_access": "Disabled",
        },
        "tags": {"env": "prod", "service": "aks"},
    },
]

MOCK_AGENT_POOLS = [
    {
        # CORRECTED: Added the real 'id' field, as provided by the API.
        "id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/managedClusters/my-test-aks-cluster/agentPools/agentpool",
        "name": "agentpool",
        "properties": {
            "provisioning_state": "Succeeded",
            "vm_size": "Standard_D2s_v3",
            "os_type": "Linux",
            "count": 3,
        },
    },
]

DESCRIBE_CLUSTERS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/\
            managedClusters/TestCluster1",
        "type": "Microsoft.ContainerService/ManagedClusters",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "TestCluster1",
        "resource_guid": "assu-ttef-vdff",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/\
            managedClusters/TestCluster2",
        "type": "Microsoft.ContainerService/ManagedClusters",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "TestCluster2",
        "resource_guid": "assu-ttef-vdff",
    },
]

DESCRIBE_CONTAINERREGISTRIES = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
        "type": "Microsoft.ContainerRegistry/registries",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "TestContainerRegistry1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
        "type": "Microsoft.ContainerRegistry/registries",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "TestContainerRegistry2",
    },
]

DESCRIBE_CONTAINERREGISTRYREPLICATIONS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/replications/repli1",
        "type": "Microsoft.ContainerRegistry/registries/replications",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "repli1",
        "container_registry_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/replications/repli2",
        "type": "Microsoft.ContainerRegistry/registries/replications",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "repli2",
        "container_registry_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
    },
]

DESCRIBE_CONTAINERREGISTRYRUNS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/runs/run1",
        "type": "Microsoft.ContainerRegistry/registries/runs",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "run1",
        "container_registry_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/runs/run2",
        "type": "Microsoft.ContainerRegistry/registries/runs",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "run2",
        "container_registry_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
    },
]

DESCRIBE_CONTAINERREGISTRYTASKS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/tasks/task1",
        "type": "Microsoft.ContainerRegistry/registries/tasks",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "task1",
        "container_registry_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/tasks/task2",
        "type": "Microsoft.ContainerRegistry/registries/tasks",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "task2",
        "container_registry_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
    },
]

DESCRIBE_CONTAINERREGISTRYWEBHOOKS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/webhooks/webhook1",
        "type": "Microsoft.ContainerRegistry/registries/webhooks",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "webhook1",
        "container_registry_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/webhooks/webhook2",
        "type": "Microsoft.ContainerRegistry/registries/webhooks",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "webhooks",
        "container_registry_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
    },
]

DESCRIBE_CONTAINERGROUPS = [
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo1",
        "type": "Microsoft.ContainerInstance/containerGroups",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "demo1",
    },
    {
        "id":
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo2",
        "type": "Microsoft.ContainerInstance/containerGroups",
        "location": "West US",
        "resource_group": "TestRG",
        "name": "demo2",
    },
]

DESCRIBE_CONTAINERS = [
    {
        "id": "container1",
        "type": "Microsoft.ContainerInstance/containers",
        "resource_group": "TestRG",
        "name": "container1",
        "container_group_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo1",
    },
    {
        "id": "container2",
        "type": "Microsoft.ContainerInstance/containers",
        "resource_group": "TestRG",
        "name": "container2",
        "container_group_id": "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo2",
    },
]
