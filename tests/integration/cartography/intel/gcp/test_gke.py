import cartography.intel.gcp.gke
import tests.data.gcp.gke
from cartography.util import run_analysis_job

TEST_WORKSPACE_ID = '1223344'
TEST_PROJECT_NUMBER = '000000000000'
TEST_UPDATE_TAG = 123456789
common_job_parameters = {
    "UPDATE_TAG": TEST_UPDATE_TAG,
    "WORKSPACE_ID": '1223344',
    "GCP_PROJECT_ID": TEST_PROJECT_NUMBER,
}


def cloudanix_workspace_to_gcp_project(neo4j_session):
    query = """
    MERGE (w:CloudanixWorkspace{id: $WorkspaceId})
    MERGE (project:GCPProject{id: $ProjectId})
    MERGE (w)-[:OWNER]->(project)
    """
    nodes = neo4j_session.run(
        query,
        WorkspaceId=TEST_WORKSPACE_ID,
        ProjectId=TEST_PROJECT_NUMBER,
    )


def test_load_gke_clusters(neo4j_session):
    data = tests.data.gcp.gke.GKE_CLUSTERS
    cartography.intel.gcp.gke.load_gke_clusters(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        # flake8: noqa
        'projects/000000000000/location/europe-west2/clusters/test-cluster',

    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GKECluster) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_eks_clusters_relationships(neo4j_session):
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
    data = tests.data.gcp.gke.GKE_CLUSTERS
    cartography.intel.gcp.gke.load_gke_clusters(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, 'projects/000000000000/location/europe-west2/clusters/test-cluster'),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GKECluster) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }
    assert actual == expected


def test_gke_public_facing(neo4j_session):

    test_load_gke_clusters(neo4j_session)
    test_load_eks_clusters_relationships(neo4j_session)
    cloudanix_workspace_to_gcp_project(neo4j_session)

    run_analysis_job('gcp_gke_asset_exposure.json', neo4j_session, common_job_parameters)

    query1 = """
    MATCH (cluster:GKECluster)<-[:RESOURCE]-(:GCPProject{id: $GCP_PROJECT_ID})<-[:OWNER]-(:GCPOrganization{id:$GCP_ORGANIZATION_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID}) \nWHERE cluster.exposed_internet=true
    RETURN cluster.name
    """

    objects = neo4j_session.run(query1, GCP_PROJECT_ID=TEST_PROJECT_NUMBER, WORKSPACE_ID=TEST_WORKSPACE_ID)

    actual_nodes = {
        (
            o['cluster.name'],

        ) for o in objects

    }

    expected_nodes = {
        (
            'test-cluster',
        ),
    }
    assert actual_nodes == expected_nodes


EXPOSURE_WORKSPACE_ID = 'ws-gke-exposure'
EXPOSURE_ORG_ID = 'org-gke-exposure'
EXPOSURE_PROJECT_ID = 'proj-gke-exposure'
EXPOSURE_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG,
    'WORKSPACE_ID': EXPOSURE_WORKSPACE_ID,
    'GCP_ORGANIZATION_ID': EXPOSURE_ORG_ID,
    'GCP_PROJECT_ID': EXPOSURE_PROJECT_ID,
}


def _seed_gke_clusters(neo4j_session, workspace_id, org_id, project_id, clusters):
    # Properties as load_gke_clusters writes them; absent keys stay unset (clusters synced before they existed).
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $workspace_id})-[:OWNER]->(o:GCPOrganization{id: $org_id})
        MERGE (o)-[:OWNER]->(p:GCPProject{id: $project_id})
        WITH p
        UNWIND $clusters AS c
        MERGE (p)-[:RESOURCE]->(cluster:GKECluster{id: c.id})
        SET cluster.name = c.id, cluster.private_nodes = c.private_nodes,
            cluster.private_endpoint_enabled = c.private_endpoint_enabled,
            cluster.master_authorized_networks = c.man,
            cluster.master_authorized_cidr_blocks = c.cidrs,
            cluster.gcp_public_cidrs_access_enabled = c.gcp_public,
            cluster.exposed_internet = c.exposed_before
        """,
        workspace_id=workspace_id, org_id=org_id, project_id=project_id, clusters=clusters,
    )


def _exposed_gke_clusters(neo4j_session, project_id):
    nodes = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $project_id})-[:RESOURCE]->(c:GKECluster{exposed_internet: true})
        RETURN c.id AS id, c.exposed_internet_type AS types, c.publicContext AS context
        """,
        project_id=project_id,
    )
    return {n['id']: sorted(n['types']) for n in nodes if n['context']}


def test_gke_public_only_when_public_endpoint_reachable_from_anywhere(neo4j_session):
    _seed_gke_clusters(
        neo4j_session, EXPOSURE_WORKSPACE_ID, EXPOSURE_ORG_ID, EXPOSURE_PROJECT_ID, [
            {'id': 'gke-no-man', 'private_nodes': True, 'private_endpoint_enabled': False, 'man': False},
            # Public endpoint locked to an office range: was public, is not.
            {
                'id': 'gke-man-restricted', 'private_nodes': False, 'private_endpoint_enabled': False, 'man': True,
                'cidrs': ['203.0.113.0/24'], 'gcp_public': False,
            },
            {
                'id': 'gke-man-open', 'private_nodes': False, 'private_endpoint_enabled': False, 'man': True,
                'cidrs': ['10.0.0.0/8', '0.0.0.0/0'],
            },
            {
                'id': 'gke-man-gcp-public', 'private_nodes': True, 'private_endpoint_enabled': False, 'man': True,
                'cidrs': [], 'gcp_public': True,
            },
            # Private endpoint, no MAN, public nodes, flagged by an earlier run: reset, not public.
            {
                'id': 'gke-private-endpoint', 'private_nodes': False, 'private_endpoint_enabled': True, 'man': False,
                'exposed_before': True,
            },
            # Synced before the ingestion fix: private_endpoint_enabled NULL means the public endpoint is on.
            {'id': 'gke-legacy-no-man', 'man': False},
            {'id': 'gke-legacy-man', 'man': True},
        ],
    )
    # Another tenant's open cluster must be left alone by this workspace's run.
    _seed_gke_clusters(
        neo4j_session, 'ws-other', 'org-other', 'proj-other',
        [{'id': 'gke-other-ws', 'private_endpoint_enabled': False, 'man': False}],
    )

    run_analysis_job('gcp_gke_asset_exposure.json', neo4j_session, EXPOSURE_JOB_PARAMETERS)

    assert _exposed_gke_clusters(neo4j_session, EXPOSURE_PROJECT_ID) == {
        'gke-no-man': ['no_master_authorized_networks', 'public_endpoint'],
        'gke-man-open': ['master_authorized_networks_open', 'public_endpoint', 'public_nodes'],
        'gke-man-gcp-public': ['gcp_public_cidrs_access', 'public_endpoint'],
        'gke-legacy-no-man': ['no_master_authorized_networks', 'public_endpoint', 'public_nodes'],
    }
    assert _exposed_gke_clusters(neo4j_session, 'proj-other') == {}
