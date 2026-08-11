from unittest.mock import MagicMock
from unittest.mock import patch

import cartography.intel.gcp.gke
import tests.data.gcp.gke
from cartography.util import run_analysis_job
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_WORKSPACE_ID = "1223344"
TEST_PROJECT_NUMBER = "000000000000"
TEST_UPDATE_TAG = 123456789
TEST_CLUSTER_ID = "https://container.googleapis.com/v1/projects/test-cluster/locations/europe-west2/clusters/test-cluster"
exposure_job_parameters = {
    "UPDATE_TAG": TEST_UPDATE_TAG,
    "WORKSPACE_ID": TEST_WORKSPACE_ID,
    "GCP_PROJECT_ID": TEST_PROJECT_NUMBER,
}


def test_load_gke_clusters(neo4j_session):
    data = tests.data.gcp.gke.GKE_RESPONSE
    cartography.intel.gcp.gke.load_gke_clusters(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        # flake8: noqa
        "https://container.googleapis.com/v1/projects/test-cluster/locations/europe-west2/clusters/test-cluster",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GKECluster) RETURN r.id;
        """,
    )

    actual_nodes = {n["r.id"] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_gke_clusters_relationships(neo4j_session):
    # Create Test GCPProject
    neo4j_session.run(
        """
        MERGE (gcp:GCPProject{id: $PROJECT_NUMBER})
        ON CREATE SET gcp.firstseen = timestamp()
        SET gcp.lastupdated = $UPDATE_TAG
        """,
        PROJECT_NUMBER=TEST_PROJECT_NUMBER,
        UPDATE_TAG=TEST_UPDATE_TAG,
    )

    # Load Test GKE Clusters
    data = tests.data.gcp.gke.GKE_RESPONSE
    cartography.intel.gcp.gke.load_gke_clusters(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            TEST_PROJECT_NUMBER,
            "https://container.googleapis.com/v1/projects/test-cluster/locations/europe-west2/clusters/test-cluster",
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GKECluster) RETURN n1.id, n2.id;
        """,
    )

    actual = {(r["n1.id"], r["n2.id"]) for r in result}

    assert actual == expected


@patch.object(
    cartography.intel.gcp.gke,
    "get_gke_clusters",
    return_value=tests.data.gcp.gke.GKE_RESPONSE,
)
def test_gke_cluster_labels(_mock_get_gke_clusters, neo4j_session):
    # Create Test GCPProject
    neo4j_session.run(
        """
        MERGE (gcp:GCPProject{id: $PROJECT_NUMBER})
        ON CREATE SET gcp.firstseen = timestamp()
        SET gcp.lastupdated = $UPDATE_TAG
        """,
        PROJECT_NUMBER=TEST_PROJECT_NUMBER,
        UPDATE_TAG=TEST_UPDATE_TAG,
    )

    common_job_parameters = {
        "UPDATE_TAG": TEST_UPDATE_TAG,
        "PROJECT_ID": TEST_PROJECT_NUMBER,
    }
    cartography.intel.gcp.gke.sync_gke_clusters(
        neo4j_session,
        MagicMock(),
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
        common_job_parameters,
    )

    # Verify GCPLabel nodes were created
    assert check_nodes(neo4j_session, "GCPLabel", ["key", "value"]) >= {
        ("env", "dev"),
        ("team", "platform"),
    }

    # Verify LABELED relationships from GKECluster to GCPLabel
    assert check_rels(
        neo4j_session,
        "GKECluster",
        "id",
        "GCPLabel",
        "id",
        "LABELED",
        rel_direction_right=True,
    ) == {
        (TEST_CLUSTER_ID, f"{TEST_CLUSTER_ID}:env:dev"),
        (TEST_CLUSTER_ID, f"{TEST_CLUSTER_ID}:team:platform"),
    }


def cloudanix_workspace_to_gcp_project(neo4j_session):
    query = """
    MERGE (w:CloudanixWorkspace{id: $WorkspaceId})
    MERGE (project:GCPProject{id: $ProjectId})
    MERGE (w)-[:OWNER]->(project)
    """
    neo4j_session.run(
        query,
        WorkspaceId=TEST_WORKSPACE_ID,
        ProjectId=TEST_PROJECT_NUMBER,
    )


def test_gke_public_facing(neo4j_session):

    test_load_gke_clusters(neo4j_session)
    test_load_gke_clusters_relationships(neo4j_session)
    cloudanix_workspace_to_gcp_project(neo4j_session)

    run_analysis_job(
        "gcp_gke_asset_exposure.json",
        neo4j_session,
        exposure_job_parameters,
    )

    query1 = """
    MATCH (cluster:GKECluster)<-[:RESOURCE]-(:GCPProject{id: $GCP_PROJECT_ID})<-[:OWNER]-(:GCPOrganization{id:$GCP_ORGANIZATION_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID}) \nWHERE cluster.exposed_internet=true
    RETURN cluster.name
    """

    objects = neo4j_session.run(
        query1,
        GCP_PROJECT_ID=TEST_PROJECT_NUMBER,
        WORKSPACE_ID=TEST_WORKSPACE_ID,
    )

    actual_nodes = {
        (o["cluster.name"],) for o in objects
    }

    expected_nodes = {
        ("test-cluster",),
    }
    assert actual_nodes == expected_nodes
