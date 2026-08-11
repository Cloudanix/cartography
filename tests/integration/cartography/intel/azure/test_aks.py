from unittest.mock import MagicMock
from unittest.mock import patch

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
from tests.data.azure.aks import MOCK_AGENT_POOLS
from tests.data.azure.aks import MOCK_CLUSTERS
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

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


def test_link_compute_to_aks(neo4j_session):
    # Guards link_compute_to_aks: BOTH AzureVirtualMachine and AzureVirtualMachineScaleSet,
    # when tagged with aks_cluster_name/_rg/_pool_name, must link via HAS_NODE to the AKS
    # cluster and its agent pool. This fails if the per-label query rewrite drops a label.
    #
    #   (AzureCluster)-[:HAS_NODE]->(vm / vmss)
    #   (AzureCluster)-[:HAS]->(AzureClusterAgentPool)-[:HAS_NODE]->(vm / vmss)
    #
    # Unique ids so this is isolated from the other (module-scoped) tests in this file.
    neo4j_session.run(
        """
        MERGE (c:AzureCluster {id: 'aks-link-cluster', name: 'AksLinkCluster', resourcegroup: 'AksLinkRG'})
        MERGE (p:AzureClusterAgentPool {id: 'aks-link-pool', name: 'akslinkpool'})
        MERGE (c)-[:HAS]->(p)
        MERGE (:AzureVirtualMachine {
            id: 'aks-link-vm',
            aks_cluster_name: 'AksLinkCluster', aks_cluster_rg: 'AksLinkRG', aks_pool_name: 'akslinkpool'
        })
        MERGE (:AzureVirtualMachineScaleSet {
            id: 'aks-link-vmss',
            aks_cluster_name: 'AksLinkCluster', aks_cluster_rg: 'AksLinkRG', aks_pool_name: 'akslinkpool'
        })
        """,
    )

    compute.link_compute_to_aks(neo4j_session, TEST_UPDATE_TAG)

    cluster_linked = {
        r['nid'] for r in neo4j_session.run(
            """
            MATCH (c:AzureCluster {id: 'aks-link-cluster'})-[:HAS_NODE]->(node)
            RETURN node.id AS nid;
            """,
        )
    }
    pool_linked = {
        r['nid'] for r in neo4j_session.run(
            """
            MATCH (p:AzureClusterAgentPool {id: 'aks-link-pool'})-[:HAS_NODE]->(node)
            RETURN node.id AS nid;
            """,
        )
    }

    assert cluster_linked == {'aks-link-vm', 'aks-link-vmss'}
    assert pool_linked == {'aks-link-vm', 'aks-link-vmss'}




@patch("cartography.intel.azure.aks.get_agent_pools")
@patch("cartography.intel.azure.aks.get_aks_clusters")
def test_sync_aks(mock_get_clusters, mock_get_pools, neo4j_session):
    """
    Test that we can correctly sync AKS cluster and agent pool data.
    """
    # Arrange
    mock_get_clusters.return_value = MOCK_CLUSTERS
    mock_get_pools.return_value = MOCK_AGENT_POOLS

    # Create the prerequisite AzureSubscription node
    neo4j_session.run(
        """
        MERGE (s:AzureSubscription{id: $sub_id})
        SET s.lastupdated = $update_tag
        """,
        sub_id=TEST_SUBSCRIPTION_ID,
        update_tag=TEST_UPDATE_TAG,
    )

    common_job_parameters = {
        "UPDATE_TAG": TEST_UPDATE_TAG,
        "AZURE_SUBSCRIPTION_ID": TEST_SUBSCRIPTION_ID,
    }

    # Act
    aks.sync(
        neo4j_session,
        MagicMock(),
        TEST_SUBSCRIPTION_ID,
        TEST_UPDATE_TAG,
        common_job_parameters,
    )

    # Assert Clusters
    public_cluster_id = MOCK_CLUSTERS[0]["id"]
    private_cluster_id = MOCK_CLUSTERS[1]["id"]
    vnet_cluster_id = MOCK_CLUSTERS[2]["id"]
    expected_nodes = {
        (public_cluster_id, "my-test-aks-cluster", True),
        (private_cluster_id, "my-private-aks-cluster", False),
        # publicNetworkAccess=Disabled closes the public path even when
        # enable_private_cluster is false (API Server VNet Integration).
        (vnet_cluster_id, "my-vnet-aks-cluster", False),
    }
    actual_nodes = check_nodes(
        neo4j_session,
        "AzureKubernetesCluster",
        ["id", "name", "api_server_public_access"],
    )
    assert actual_nodes == expected_nodes

    expected_rels = {
        (TEST_SUBSCRIPTION_ID, public_cluster_id),
        (TEST_SUBSCRIPTION_ID, private_cluster_id),
        (TEST_SUBSCRIPTION_ID, vnet_cluster_id),
    }
    actual_rels = check_rels(
        neo4j_session,
        "AzureSubscription",
        "id",
        "AzureKubernetesCluster",
        "id",
        "RESOURCE",
    )
    assert actual_rels == expected_rels

    # Assert Agent Pools (the same mocked pool is attached to every cluster in this fixture).
    pool_id = MOCK_AGENT_POOLS[0]["id"]

    expected_pool_nodes = {(pool_id, "agentpool")}
    actual_pool_nodes = check_nodes(
        neo4j_session, "AzureKubernetesAgentPool", ["id", "name"]
    )
    assert actual_pool_nodes == expected_pool_nodes

    expected_pool_rels = {
        (public_cluster_id, pool_id),
        (private_cluster_id, pool_id),
        (vnet_cluster_id, pool_id),
    }
    actual_pool_rels = check_rels(
        neo4j_session,
        "AzureKubernetesCluster",
        "id",
        "AzureKubernetesAgentPool",
        "id",
        "HAS_AGENT_POOL",
    )
    assert actual_pool_rels == expected_pool_rels


def test_load_aks_tags(neo4j_session):
    """
    Test that we can correctly sync Azure AKS tags.
    """
    # Arrange: Create the prerequisite AzureSubscription node
    neo4j_session.run(
        """
        MERGE (s:AzureSubscription{id: $sub_id})
        SET s.lastupdated = $update_tag
        """,
        sub_id=TEST_SUBSCRIPTION_ID,
        update_tag=TEST_UPDATE_TAG,
    )
    # Load the cluster so it exists to be tagged
    aks.load_aks_clusters(
        neo4j_session,
        aks.transform_aks_clusters(MOCK_CLUSTERS),
        TEST_SUBSCRIPTION_ID,
        TEST_UPDATE_TAG,
    )

    # Act: Load the tags
    aks.load_aks_tags(
        neo4j_session,
        TEST_SUBSCRIPTION_ID,
        MOCK_CLUSTERS,
        TEST_UPDATE_TAG,
    )

    # Assert: Check for the 2 unique tags
    expected_tags = {
        f"{TEST_SUBSCRIPTION_ID}|env:prod",
        f"{TEST_SUBSCRIPTION_ID}|service:aks",
    }
    tag_nodes = neo4j_session.run("MATCH (t:AzureTag) RETURN t.id")
    actual_tags = {n["t.id"] for n in tag_nodes}
    assert actual_tags == expected_tags

    # Assert: Check the relationships (every fixture cluster carries the same tags).
    expected_rels = {
        (cluster["id"], f"{TEST_SUBSCRIPTION_ID}|{key}:{value}")
        for cluster in MOCK_CLUSTERS
        for key, value in cluster["tags"].items()
    }
    actual_rels = check_rels(
        neo4j_session,
        "AzureKubernetesCluster",
        "id",
        "AzureTag",
        "id",
        "TAGGED",
    )
    assert actual_rels == expected_rels
