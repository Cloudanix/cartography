from cartography.intel.azure import aks
from cartography.intel.azure import compute
from tests.data.azure.aks import DESCRIBE_CLUSTERS
from tests.data.azure.aks import DESCRIBE_CONTAINERGROUPS
from tests.data.azure.aks import DESCRIBE_CONTAINERREGISTRIES
from tests.data.azure.aks import DESCRIBE_CONTAINERREGISTRYREPLICATIONS
from tests.data.azure.aks import DESCRIBE_CONTAINERREGISTRYRUNS
from tests.data.azure.aks import DESCRIBE_CONTAINERREGISTRYTASKS
from tests.data.azure.aks import DESCRIBE_CONTAINERREGISTRYWEBHOOKS
from tests.data.azure.aks import DESCRIBE_CONTAINERS

TEST_SUBSCRIPTION_ID = '00-00-00-00'
TEST_RESOURCE_GROUP = 'TestRG'
TEST_UPDATE_TAG = 123456789


def test_load_clusters(neo4j_session):
    aks.load_aks(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CLUSTERS,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/\
            managedClusters/TestCluster1",
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/\
            managedClusters/TestCluster2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AzureCluster) RETURN r.id;
        """, )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_network_relationships(neo4j_session):
    neo4j_session.run(
        """
        MERGE (as:AzureSubscription{id: $subscription_id})
        ON CREATE SET as.firstseen = timestamp()
        SET as.lastupdated = $update_tag
        """,
        subscription_id=TEST_SUBSCRIPTION_ID,
        update_tag=TEST_UPDATE_TAG,
    )

    aks.load_aks(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CLUSTERS,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            TEST_SUBSCRIPTION_ID,
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/\
            managedClusters/TestCluster1",
        ),
        (
            TEST_SUBSCRIPTION_ID,
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerService/\
            managedClusters/TestCluster2",
        ),
    }

    result = neo4j_session.run(
        """
        MATCH (n1:AzureSubscription)-[:RESOURCE]->(n2:AzureCluster) RETURN n1.id, n2.id;
        """, )

    actual = {(r['n1.id'], r['n2.id']) for r in result}

    assert actual == expected


def test_load_container_registries(neo4j_session):
    aks.load_container_registries(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERREGISTRIES,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AzureContainerRegistry) RETURN r.id;
        """, )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_container_registry_relationships(neo4j_session):
    neo4j_session.run(
        """
        MERGE (as:AzureSubscription{id: $subscription_id})
        ON CREATE SET as.firstseen = timestamp()
        SET as.lastupdated = $update_tag
        """,
        subscription_id=TEST_SUBSCRIPTION_ID,
        update_tag=TEST_UPDATE_TAG,
    )

    aks.load_container_registries(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERREGISTRIES,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            TEST_SUBSCRIPTION_ID,
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
        ),
        (
            TEST_SUBSCRIPTION_ID,
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
        ),
    }

    result = neo4j_session.run(
        """
        MATCH (n1:AzureSubscription)-[:RESOURCE]->(n2:AzureContainerRegistry) RETURN n1.id, n2.id;
        """, )

    actual = {(r['n1.id'], r['n2.id']) for r in result}

    assert actual == expected


def test_load_container_registry_replications(neo4j_session):
    aks.load_container_registry_replications(
        neo4j_session,
        DESCRIBE_CONTAINERREGISTRYREPLICATIONS,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/replications/repli1",
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/replications/repli2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AzureContainerRegistryReplication) RETURN r.id;
        """, )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_container_registry_replication_relationships(neo4j_session):
    aks.load_container_registries(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERREGISTRIES,
        TEST_UPDATE_TAG,
    )

    aks.load_container_registry_replications(
        neo4j_session,
        DESCRIBE_CONTAINERREGISTRYREPLICATIONS,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/replications/repli1",
        ),
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/replications/repli2",
        ),
    }

    result = neo4j_session.run(
        """
        MATCH (n1:AzureContainerRegistry)-[:CONTAIN]->(n2:AzureContainerRegistryReplication) RETURN n1.id, n2.id;
        """, )

    actual = {(r['n1.id'], r['n2.id']) for r in result}

    assert actual == expected


def test_load_container_registry_runs(neo4j_session):
    aks.load_container_registry_runs(
        neo4j_session,
        DESCRIBE_CONTAINERREGISTRYRUNS,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/runs/run1",
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/runs/run2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AzureContainerRegistryRun) RETURN r.id;
        """, )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_container_registry_run_relationships(neo4j_session):
    aks.load_container_registries(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERREGISTRIES,
        TEST_UPDATE_TAG,
    )

    aks.load_container_registry_runs(
        neo4j_session,
        DESCRIBE_CONTAINERREGISTRYRUNS,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/runs/run1",
        ),
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/runs/run2",
        ),
    }

    result = neo4j_session.run(
        """
        MATCH (n1:AzureContainerRegistry)-[:CONTAIN]->(n2:AzureContainerRegistryRun) RETURN n1.id, n2.id;
        """, )

    actual = {(r['n1.id'], r['n2.id']) for r in result}

    assert actual == expected


def test_load_container_registry_tasks(neo4j_session):
    aks.load_container_registry_tasks(
        neo4j_session,
        DESCRIBE_CONTAINERREGISTRYTASKS,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/tasks/task1",
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/tasks/task2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AzureContainerRegistryTask) RETURN r.id;
        """, )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_container_registry_task_relationships(neo4j_session):
    aks.load_container_registries(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERREGISTRIES,
        TEST_UPDATE_TAG,
    )

    aks.load_container_registry_tasks(
        neo4j_session,
        DESCRIBE_CONTAINERREGISTRYTASKS,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/tasks/task1",
        ),
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/tasks/task2",
        ),
    }

    result = neo4j_session.run(
        """
        MATCH (n1:AzureContainerRegistry)-[:CONTAIN]->(n2:AzureContainerRegistryTask) RETURN n1.id, n2.id;
        """, )

    actual = {(r['n1.id'], r['n2.id']) for r in result}

    assert actual == expected


def test_load_container_registry_webhooks(neo4j_session):
    aks.load_container_registry_webhooks(
        neo4j_session,
        DESCRIBE_CONTAINERREGISTRYWEBHOOKS,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/webhooks/webhook1",
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/webhooks/webhook2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AzureContainerRegistryWebhook) RETURN r.id;
        """, )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_container_registry_webhook_relationships(neo4j_session):
    aks.load_container_registries(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERREGISTRIES,
        TEST_UPDATE_TAG,
    )

    aks.load_container_registry_webhooks(
        neo4j_session,
        DESCRIBE_CONTAINERREGISTRYWEBHOOKS,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry1",
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry1/webhooks/webhook1",
        ),
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerRegistry/registries/TestContainerRegistry2",
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/Microsoft.ContainerRegistry/\
            registries/TestContainerRegistry2/webhooks/webhook2",
        ),
    }

    result = neo4j_session.run(
        """
        MATCH (n1:AzureContainerRegistry)-[:CONTAIN]->(n2:AzureContainerRegistryWebhook) RETURN n1.id, n2.id;
        """, )

    actual = {(r['n1.id'], r['n2.id']) for r in result}

    assert actual == expected


def test_load_container_groups(neo4j_session):
    aks.load_container_groups(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERGROUPS,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo1",
        "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AzureContainerGroup) RETURN r.id;
        """, )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_container_group_relationships(neo4j_session):
    neo4j_session.run(
        """
        MERGE (as:AzureSubscription{id: $subscription_id})
        ON CREATE SET as.firstseen = timestamp()
        SET as.lastupdated = $update_tag
        """,
        subscription_id=TEST_SUBSCRIPTION_ID,
        update_tag=TEST_UPDATE_TAG,
    )

    aks.load_container_groups(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERGROUPS,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            TEST_SUBSCRIPTION_ID,
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo1",
        ),
        (
            TEST_SUBSCRIPTION_ID,
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo2",
        ),
    }

    result = neo4j_session.run(
        """
        MATCH (n1:AzureSubscription)-[:RESOURCE]->(n2:AzureContainerGroup) RETURN n1.id, n2.id;
        """, )

    actual = {(r['n1.id'], r['n2.id']) for r in result}

    assert actual == expected


def test_load_containers(neo4j_session):
    aks.load_containers(
        neo4j_session,
        DESCRIBE_CONTAINERS,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "container2",
        "container1",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AzureContainer) RETURN r.id;
        """, )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_container_relationships(neo4j_session):
    aks.load_container_groups(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        DESCRIBE_CONTAINERGROUPS,
        TEST_UPDATE_TAG,
    )

    aks.load_containers(
        neo4j_session,
        DESCRIBE_CONTAINERS,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo2",
            "container2",
        ),
        (
            "/subscriptions/00-00-00-00/resourceGroups/TestRG/providers/\
            Microsoft.ContainerInstance/containerGroups/demo1",
            "container1",
        ),
    }

    result = neo4j_session.run(
        """
        MATCH (n1:AzureContainerGroup)-[:CONTAIN]->(n2:AzureContainer) RETURN n1.id, n2.id;
        """, )

    actual = {(r['n1.id'], r['n2.id']) for r in result}

    assert actual == expected


def test_sync_aks_node_links(neo4j_session):
    # Guards sync_aks_node_links: BOTH AzureVirtualMachine and AzureVirtualMachineScaleSet link
    # via HAS_NODE to the AKS cluster and its agent pool, matched by
    #   - the cluster's node resource group (MC_*), case-insensitively, with no cluster tags, or
    #   - the aks-managed-cluster-name/-rg tags, case-insensitively;
    # and never across subscriptions/workspaces, even with identical names and tags.
    #
    #   (AzureCluster)-[:HAS_NODE]->(vm / vmss)
    #   (AzureCluster)-[:HAS]->(AzureClusterAgentPool)-[:HAS_NODE]->(vm / vmss)
    #
    # Unique ids so this is isolated from the other (module-scoped) tests in this file.
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace {id: 'aksl-w1'})-[:OWNER]->(:AzureTenant {id: 'aksl-t1'})
            -[:RESOURCE]->(s1:AzureSubscription {id: 'aksl-s1'})
        MERGE (:CloudanixWorkspace {id: 'aksl-w2'})-[:OWNER]->(:AzureTenant {id: 'aksl-t2'})
            -[:RESOURCE]->(s2:AzureSubscription {id: 'aksl-s2'})
        MERGE (s1)-[:RESOURCE]->(c:AzureCluster {
            id: 'aksl-cluster', name: 'AksLinkCluster', resourcegroup: 'akslinkrg',
            node_resource_group: 'mc_akslinkrg_akslinkcluster_eastus'
        })
        MERGE (c)-[:HAS]->(:AzureClusterAgentPool {id: 'aksl-pool', name: 'nodepool1'})
        MERGE (s1)-[:RESOURCE]->(:AzureVirtualMachineScaleSet {
            id: 'aksl-vmss-noderg', resourcegroup: 'MC_AksLinkRG_AksLinkCluster_eastus', aks_pool_name: 'nodepool1'
        })
        MERGE (s1)-[:RESOURCE]->(:AzureVirtualMachine {
            id: 'aksl-vm-tags', resourcegroup: 'other',
            aks_cluster_name: 'AksLinkCluster', aks_cluster_rg: 'AksLinkRG', aks_pool_name: 'NodePool1'
        })
        MERGE (s1)-[:RESOURCE]->(:AzureVirtualMachine {id: 'aksl-vm-unrelated', resourcegroup: 'other'})
        MERGE (s2)-[:RESOURCE]->(:AzureVirtualMachineScaleSet {
            id: 'aksl-vmss-foreign', resourcegroup: 'MC_AksLinkRG_AksLinkCluster_eastus',
            aks_cluster_name: 'AksLinkCluster', aks_cluster_rg: 'AksLinkRG', aks_pool_name: 'nodepool1'
        })
        MERGE (s1)-[:RESOURCE]->(old:AzureVirtualMachine {id: 'aksl-vm-old', resourcegroup: 'other'})
        MERGE (c)-[:HAS_NODE {lastupdated: 1}]->(old)
        """,
    )

    compute.sync_aks_node_links(
        neo4j_session,
        {
            'WORKSPACE_ID': 'aksl-w1',
            'AZURE_TENANT_ID': 'aksl-t1',
            'AZURE_SUBSCRIPTION_ID': 'aksl-s1',
            'UPDATE_TAG': TEST_UPDATE_TAG,
        },
    )

    links = {
        (r['s'], r['n']) for r in neo4j_session.run(
            """
            MATCH (s)-[:HAS_NODE]->(n) WHERE n.id STARTS WITH 'aksl-'
            RETURN s.id AS s, n.id AS n
            """,
        )
    }
    assert links == {
        ('aksl-cluster', 'aksl-vmss-noderg'),
        ('aksl-cluster', 'aksl-vm-tags'),
        ('aksl-pool', 'aksl-vmss-noderg'),
        ('aksl-pool', 'aksl-vm-tags'),
    }
