"""
Tests for cartography/intel/gcp/gke.py

Run with:
    pytest tests/unit/cartography/intel/gcp/test_gke.py -v

These tests use Neo4j's test session helper (neo4j_session fixture provided by
cartography's conftest.py) and the static GKE_RESPONSE fixture defined in
tests/data/gke.py.
"""
import pytest

# ---------------------------------------------------------------------------
# Test fixtures / static data
# ---------------------------------------------------------------------------

# Inline here so the test file is self-contained; in the real repo this lives
# in tests/data/gke.py and is imported as:
#   from tests.data.gke import GKE_RESPONSE
GKE_RESPONSE = {
    'clusters': [{
        'selfLink': 'https://container.googleapis.com/v1/projects/test-project/locations/europe-west2/clusters/test-cluster',
        'createTime': '2019-01-01T00:00:00+00:00',
        'name': 'test-cluster',
        'description': 'Test cluster',
        'loggingService': 'logging.googleapis.com',
        'monitoringService': 'none',
        'network': 'test-cluster',
        'subnetwork': 'test-cluster',
        'clusterIpv4Cidr': '10.0.0.0/14',
        'zone': 'europe-west2',
        'location': 'europe-west2',
        'endpoint': '10.0.0.1',
        'initialClusterVersion': '1.12.10-gke.15',
        'currentMasterVersion': '1.14.10-gke.27',
        'status': 'RUNNING',
        'servicesIpv4Cidr': '10.4.0.0/15',
        'databaseEncryption': {'state': 'DECRYPTED'},
        'networkPolicy': {'provider': 'CALICO', 'enabled': True},
        'masterAuthorizedNetworksConfig': {'enabled': True},
        'legacyAbac': {},
        'shieldedNodes': {},
        'privateClusterConfig': {
            'enablePrivateNodes': True,
            'enablePrivateEndpoint': True,
            'masterIpv4CidrBlock': '10.8.0.0/28',
            'privateEndpoint': '10.8.0.2',
            'publicEndpoint': '34.0.0.1',
        },
        'masterAuth': {'clusterCaCertificate': 'abc123'},
        'nodePools': [
            {
                'name': 'default-pool',
                'config': {
                    'machineType': 'n1-standard-8',
                    'diskSizeGb': 50,
                    'imageType': 'COS',
                    'diskType': 'pd-standard',
                },
                'initialNodeCount': 2,
                'management': {'autoRepair': True},
                'maxPodsConstraint': {'maxPodsPerNode': '10'},
                'selfLink': 'https://container.googleapis.com/v1/projects/test-project/locations/europe-west2/clusters/test-cluster/nodePools/default-pool',
                'version': '1.14.10-gke.17',
                'status': 'RUNNING',
            },
            {
                'name': 'gpu-pool',
                'config': {
                    'machineType': 'n1-standard-4',
                    'diskSizeGb': 100,
                    'imageType': 'COS',
                    'diskType': 'pd-ssd',
                },
                'initialNodeCount': 1,
                'management': {'autoRepair': False},
                'maxPodsConstraint': {'maxPodsPerNode': '8'},
                'selfLink': 'https://container.googleapis.com/v1/projects/test-project/locations/europe-west2/clusters/test-cluster/nodePools/gpu-pool',
                'version': '1.14.10-gke.17',
                'status': 'RUNNING',
            },
        ],
    }],
}

TEST_PROJECT_ID = 'test-project'
TEST_UPDATE_TAG = 123456789


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_cluster_id(project_id: str, cluster_name: str) -> str:
    return f"project/{project_id}/clusters/{cluster_name}"


def _get_node_pool_id(project_id: str, cluster_name: str, pool_name: str) -> str:
    return f"project/{project_id}/clusters/{cluster_name}/nodePools/{pool_name}"


# ---------------------------------------------------------------------------
# Tests: load_gke_clusters
# ---------------------------------------------------------------------------

def test_load_gke_clusters_creates_cluster_node(neo4j_session):
    from cartography.intel.gcp.gke import load_gke_clusters

    load_gke_clusters(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    result = neo4j_session.run(
        "MATCH (c:GKECluster{id:{Id}}) RETURN c",
        Id=_get_cluster_id(TEST_PROJECT_ID, 'test-cluster'),
    ).data()

    assert len(result) == 1
    cluster = result[0]['c']
    assert cluster['name'] == 'test-cluster'
    assert cluster['status'] == 'RUNNING'
    assert cluster['location'] == 'europe-west2'
    assert cluster['network_policy'] == 'CALICO'
    assert cluster['private_nodes'] is True
    assert cluster['lastupdated'] == TEST_UPDATE_TAG


def test_load_gke_clusters_creates_project_relationship(neo4j_session):
    from cartography.intel.gcp.gke import load_gke_clusters

    # GCPProject node must already exist for the MATCH in the query
    neo4j_session.run(
        "MERGE (p:GCPProject{id:{Id}})",
        Id=TEST_PROJECT_ID,
    )

    load_gke_clusters(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    result = neo4j_session.run(
        """
        MATCH (p:GCPProject{id:{ProjectId}})-[:RESOURCE]->(c:GKECluster)
        RETURN c.name AS name
        """,
        ProjectId=TEST_PROJECT_ID,
    ).data()

    assert len(result) == 1
    assert result[0]['name'] == 'test-cluster'


def test_load_gke_clusters_empty_response(neo4j_session):
    """An empty or missing-clusters response must not raise."""
    from cartography.intel.gcp.gke import load_gke_clusters

    load_gke_clusters(neo4j_session, {}, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    result = neo4j_session.run("MATCH (c:GKECluster) RETURN c").data()
    assert len(result) == 0


# ---------------------------------------------------------------------------
# Tests: load_gke_node_pools
# ---------------------------------------------------------------------------

def test_load_gke_node_pools_creates_node_pool_nodes(neo4j_session):
    from cartography.intel.gcp.gke import load_gke_clusters, load_gke_node_pools

    load_gke_clusters(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)
    load_gke_node_pools(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    result = neo4j_session.run("MATCH (p:GKENodePool) RETURN p ORDER BY p.name").data()
    assert len(result) == 2

    names = {r['p']['name'] for r in result}
    assert names == {'default-pool', 'gpu-pool'}


def test_load_gke_node_pools_correct_properties(neo4j_session):
    from cartography.intel.gcp.gke import load_gke_clusters, load_gke_node_pools

    load_gke_clusters(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)
    load_gke_node_pools(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    pool_id = _get_node_pool_id(TEST_PROJECT_ID, 'test-cluster', 'default-pool')
    result = neo4j_session.run(
        "MATCH (p:GKENodePool{id:{Id}}) RETURN p",
        Id=pool_id,
    ).data()

    assert len(result) == 1
    pool = result[0]['p']
    assert pool['name'] == 'default-pool'
    assert pool['status'] == 'RUNNING'
    assert pool['machine_type'] == 'n1-standard-8'
    assert pool['disk_size_gb'] == 50
    assert pool['image_type'] == 'COS'
    assert pool['auto_repair'] is True
    assert pool['max_pods_per_node'] == '10'
    assert pool['lastupdated'] == TEST_UPDATE_TAG
    assert pool['cluster_id'] == _get_cluster_id(TEST_PROJECT_ID, 'test-cluster')


def test_load_gke_node_pools_creates_has_node_pool_relationship(neo4j_session):
    from cartography.intel.gcp.gke import load_gke_clusters, load_gke_node_pools

    load_gke_clusters(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)
    load_gke_node_pools(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    result = neo4j_session.run(
        """
        MATCH (c:GKECluster{id:{ClusterId}})-[:HAS_NODE_POOL]->(p:GKENodePool)
        RETURN p.name AS name
        ORDER BY p.name
        """,
        ClusterId=_get_cluster_id(TEST_PROJECT_ID, 'test-cluster'),
    ).data()

    assert len(result) == 2
    assert result[0]['name'] == 'default-pool'
    assert result[1]['name'] == 'gpu-pool'


def test_load_gke_node_pools_is_idempotent(neo4j_session):
    """Running load_gke_node_pools twice must not create duplicate nodes or relationships."""
    from cartography.intel.gcp.gke import load_gke_clusters, load_gke_node_pools

    load_gke_clusters(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)
    load_gke_node_pools(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)
    load_gke_node_pools(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    pools = neo4j_session.run("MATCH (p:GKENodePool) RETURN p").data()
    assert len(pools) == 2

    rels = neo4j_session.run("MATCH (:GKECluster)-[r:HAS_NODE_POOL]->(:GKENodePool) RETURN r").data()
    assert len(rels) == 2


def test_load_gke_node_pools_empty_cluster_response(neo4j_session):
    """An empty response must not raise and must not create any pool nodes."""
    from cartography.intel.gcp.gke import load_gke_node_pools

    load_gke_node_pools(neo4j_session, {}, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    result = neo4j_session.run("MATCH (p:GKENodePool) RETURN p").data()
    assert len(result) == 0


def test_load_gke_node_pools_cluster_with_no_node_pools(neo4j_session):
    """A cluster that has no nodePools key must not raise."""
    from cartography.intel.gcp.gke import load_gke_clusters, load_gke_node_pools

    response_no_pools = {
        'clusters': [{
            **GKE_RESPONSE['clusters'][0],
            'nodePools': [],
        }],
    }

    load_gke_clusters(neo4j_session, response_no_pools, TEST_PROJECT_ID, TEST_UPDATE_TAG)
    load_gke_node_pools(neo4j_session, response_no_pools, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    result = neo4j_session.run("MATCH (p:GKENodePool) RETURN p").data()
    assert len(result) == 0


# ---------------------------------------------------------------------------
# Tests: compute.py – GKE label extraction
# ---------------------------------------------------------------------------

def test_transform_gcp_instances_extracts_gke_labels():
    """
    transform_gcp_instances should read goog-gke-cluster-name and goog-gke-nodepool
    labels and expose them as gke_cluster_name / gke_node_pool_name.
    """
    from cartography.intel.gcp.compute import transform_gcp_instances

    response_objects = [
        {
            'id': 'projects/test-project/zones/europe-west2-a/instances',
            'items': [
                {
                    'name': 'gke-node-1',
                    'selfLink': 'https://www.googleapis.com/compute/v1/projects/test-project/zones/europe-west2-a/instances/gke-node-1',
                    'status': 'RUNNING',
                    'labels': {
                        'goog-gke-cluster-name': 'test-cluster',
                        'goog-gke-nodepool': 'default-pool',
                    },
                    'networkInterfaces': [
                        {
                            'subnetwork': 'https://www.googleapis.com/compute/v1/projects/test-project/regions/europe-west2/subnetworks/test-subnet',
                            'network': 'https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-network',
                        },
                    ],
                },
            ],
        },
    ]

    instances = transform_gcp_instances(response_objects)

    assert len(instances) == 1
    assert instances[0]['gke_cluster_name'] == 'test-cluster'
    assert instances[0]['gke_node_pool_name'] == 'default-pool'


def test_transform_gcp_instances_no_gke_labels():
    """Instances without GKE labels should have None for both GKE fields."""
    from cartography.intel.gcp.compute import transform_gcp_instances

    response_objects = [
        {
            'id': 'projects/test-project/zones/europe-west2-a/instances',
            'items': [
                {
                    'name': 'plain-vm',
                    'selfLink': 'https://www.googleapis.com/compute/v1/projects/test-project/zones/europe-west2-a/instances/plain-vm',
                    'status': 'RUNNING',
                    'networkInterfaces': [
                        {
                            'subnetwork': 'https://www.googleapis.com/compute/v1/projects/test-project/regions/europe-west2/subnetworks/test-subnet',
                            'network': 'https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-network',
                        },
                    ],
                },
            ],
        },
    ]

    instances = transform_gcp_instances(response_objects)

    assert len(instances) == 1
    assert instances[0]['gke_cluster_name'] is None
    assert instances[0]['gke_node_pool_name'] is None


# ---------------------------------------------------------------------------
# Tests: compute.py – GKE node relationship creation
# ---------------------------------------------------------------------------

def test_load_gcp_instances_links_to_gke_cluster_and_pool(neo4j_session):
    """
    After loading a GKE-labeled instance, there should be:
      (GKECluster)-[:HAS_NODE]->(GCPInstance)
      (GKENodePool)-[:HAS_NODE]->(GCPInstance)
    """
    from cartography.intel.gcp.gke import load_gke_clusters, load_gke_node_pools
    from cartography.intel.gcp.compute import load_gcp_instances

    # First populate cluster and node pool nodes
    neo4j_session.run("MERGE (p:GCPProject{id:{Id}})", Id=TEST_PROJECT_ID)
    load_gke_clusters(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)
    load_gke_node_pools(neo4j_session, GKE_RESPONSE, TEST_PROJECT_ID, TEST_UPDATE_TAG)

    # Now ingest an instance that carries GKE labels
    instance_list = [
        {
            'partial_uri': 'projects/test-project/zones/europe-west2-a/instances/gke-node-1',
            'project_id': TEST_PROJECT_ID,
            'selfLink': 'https://www.googleapis.com/compute/v1/projects/test-project/zones/europe-west2-a/instances/gke-node-1',
            'name': 'gke-node-1',
            'zone_name': 'europe-west2-a',
            'status': 'RUNNING',
            'gke_cluster_name': 'test-cluster',
            'gke_node_pool_name': 'default-pool',
            'networkInterfaces': [],
            'tags': {},
        },
    ]

    load_gcp_instances(neo4j_session, instance_list, TEST_UPDATE_TAG)

    # Verify cluster → node relationship
    cluster_result = neo4j_session.run(
        """
        MATCH (c:GKECluster{id:{ClusterId}})-[:HAS_NODE]->(i:GCPInstance{id:{InstanceId}})
        RETURN i.instancename AS name
        """,
        ClusterId=_get_cluster_id(TEST_PROJECT_ID, 'test-cluster'),
        InstanceId='projects/test-project/zones/europe-west2-a/instances/gke-node-1',
    ).data()
    assert len(cluster_result) == 1
    assert cluster_result[0]['name'] == 'gke-node-1'

    # Verify node pool → node relationship
    pool_result = neo4j_session.run(
        """
        MATCH (p:GKENodePool{id:{PoolId}})-[:HAS_NODE]->(i:GCPInstance{id:{InstanceId}})
        RETURN i.instancename AS name
        """,
        PoolId=_get_node_pool_id(TEST_PROJECT_ID, 'test-cluster', 'default-pool'),
        InstanceId='projects/test-project/zones/europe-west2-a/instances/gke-node-1',
    ).data()
    assert len(pool_result) == 1
    assert pool_result[0]['name'] == 'gke-node-1'


def test_load_gcp_instances_no_gke_links_for_plain_vms(neo4j_session):
    """Plain VMs (no GKE labels) must not generate any HAS_NODE relationships."""
    from cartography.intel.gcp.compute import load_gcp_instances

    instance_list = [
        {
            'partial_uri': 'projects/test-project/zones/europe-west2-a/instances/plain-vm',
            'project_id': TEST_PROJECT_ID,
            'selfLink': 'https://www.googleapis.com/compute/v1/projects/test-project/zones/europe-west2-a/instances/plain-vm',
            'name': 'plain-vm',
            'zone_name': 'europe-west2-a',
            'status': 'RUNNING',
            'gke_cluster_name': None,
            'gke_node_pool_name': None,
            'networkInterfaces': [],
            'tags': {},
        },
    ]

    load_gcp_instances(neo4j_session, instance_list, TEST_UPDATE_TAG)

    result = neo4j_session.run(
        "MATCH ()-[r:HAS_NODE]->() RETURN r",
    ).data()
    assert len(result) == 0
