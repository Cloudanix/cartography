from unittest.mock import MagicMock

import cartography.intel.gcp.cloudrun
import tests.data.gcp.cloudrun

TEST_PROJECT_NUMBER = '000000000000'
TEST_UPDATE_TAG = 123456789


def test_load_cloudrun_authorized_domains(neo4j_session):
    data = tests.data.gcp.cloudrun.CLOUDRUN_AUTHORIZED_DOMAINS
    cartography.intel.gcp.cloudrun.load_cloudrun_authorized_domains(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'example123.com',
        'example456.com',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPCloudRunAuthorizedDomain) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_cloudrun_configurations(neo4j_session):
    data = tests.data.gcp.cloudrun.CLOUDRUN_CONFIGURATIONS
    cartography.intel.gcp.cloudrun.load_cloudrun_configurations(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'configuration123',
        'configuration456',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPCloudRunConfiguration) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_cloudrun_domainmappings(neo4j_session):
    data = tests.data.gcp.cloudrun.CLOUDRUN_DOMAIN_MAPPINGS
    cartography.intel.gcp.cloudrun.load_cloudrun_domainmappings(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'domainmap123',
        'domainmap456',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPCloudRunDomainMap) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_cloudrun_revisions(neo4j_session):
    data = tests.data.gcp.cloudrun.CLOUDRUN_REVISIONS
    cartography.intel.gcp.cloudrun.load_cloudrun_revisions(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'revision123',
        'revision456',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPCloudRunRevision) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_cloudrun_routes(neo4j_session):
    data = tests.data.gcp.cloudrun.CLOUDRUN_ROUTES
    cartography.intel.gcp.cloudrun.load_cloudrun_routes(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'route123',
        'route456',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPCloudRunRoute) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_cloudrun_services(neo4j_session):
    data = tests.data.gcp.cloudrun.CLOUDRUN_SERVICES
    cartography.intel.gcp.cloudrun.load_cloudrun_services(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'service123',
        'service456',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPCloudRunService) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_authorized_domains_relationships(neo4j_session):
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

    # Load Test Authorized Domains
    data = tests.data.gcp.cloudrun.CLOUDRUN_AUTHORIZED_DOMAINS
    cartography.intel.gcp.cloudrun.load_cloudrun_authorized_domains(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, "example123.com"),
        (TEST_PROJECT_NUMBER, "example456.com"),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GCPCloudRunAuthorizedDomain) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_configurations_relationships(neo4j_session):
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

    # Load Test Configurations
    data = tests.data.gcp.cloudrun.CLOUDRUN_CONFIGURATIONS
    cartography.intel.gcp.cloudrun.load_cloudrun_configurations(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, "configuration123"),
        (TEST_PROJECT_NUMBER, "configuration456"),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GCPCloudRunConfiguration) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_domainmappings_relationships(neo4j_session):
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

    # Load Test Domain Mappings
    data = tests.data.gcp.cloudrun.CLOUDRUN_DOMAIN_MAPPINGS
    cartography.intel.gcp.cloudrun.load_cloudrun_domainmappings(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, "domainmap123"),
        (TEST_PROJECT_NUMBER, "domainmap456"),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GCPCloudRunDomainMap) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_revisions_relationships(neo4j_session):
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

    # Load Test Revisions
    data = tests.data.gcp.cloudrun.CLOUDRUN_REVISIONS
    cartography.intel.gcp.cloudrun.load_cloudrun_revisions(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, "revision123"),
        (TEST_PROJECT_NUMBER, "revision456"),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GCPCloudRunRevision) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_routes_relationships(neo4j_session):
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

    # Load Test Routes
    data = tests.data.gcp.cloudrun.CLOUDRUN_ROUTES
    cartography.intel.gcp.cloudrun.load_cloudrun_routes(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, "route123"),
        (TEST_PROJECT_NUMBER, "route456"),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GCPCloudRunRoute) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_services_relationships(neo4j_session):
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

    # Load Test Services
    data = tests.data.gcp.cloudrun.CLOUDRUN_SERVICES
    cartography.intel.gcp.cloudrun.load_cloudrun_services(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, "service123"),
        (TEST_PROJECT_NUMBER, "service456"),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GCPCloudRunService) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


SYNC_PROJECT = 'proj-run-sync'
SYNC_PARAMS = {
    'UPDATE_TAG': 200, 'WORKSPACE_ID': 'ws-run-sync', 'GCP_ORGANIZATION_ID': 'org-run-sync',
    'GCP_PROJECT_ID': SYNC_PROJECT, 'LIMIT_SIZE': 1000,
}


def _run_client(services):
    """Cloud Run v1 client whose list calls return nothing but the given services (one page)."""
    client = MagicMock()
    namespaces = client.namespaces.return_value
    for collection in ('authorizeddomains', 'configurations', 'domainmappings', 'revisions', 'routes', 'services'):
        getattr(namespaces, collection).return_value.list.return_value.execute.return_value = {}
    namespaces.authorizeddomains.return_value.list_next.return_value = None
    namespaces.services.return_value.list.return_value.execute.return_value = {'items': services}
    return client


def test_sync_writes_services_and_removes_stale_ones(neo4j_session, mocker):
    mocker.patch.object(cartography.intel.gcp.cloudrun.gcp_console_link, 'get_console_link', return_value='link')
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(o:GCPOrganization{id: $org})
        MERGE (o)-[:OWNER]->(p:GCPProject{id: $project})
        MERGE (p)-[:RESOURCE]->(:GCPCloudRunService{id: 'projects/proj-run-sync/services/deleted', lastupdated: 100})
        """,
        ws=SYNC_PARAMS['WORKSPACE_ID'], org=SYNC_PARAMS['GCP_ORGANIZATION_ID'], project=SYNC_PROJECT,
    )
    services = [{
        'metadata': {
            'name': 'web', 'namespace': '123456', 'uid': 'uid-web',
            'labels': {'cloud.googleapis.com/location': 'us-central1'},
            'annotations': {'run.googleapis.com/ingress': 'all'},
        },
        'status': {'url': 'https://web-abc-uc.a.run.app', 'latestReadyRevisionName': 'web-00001'},
    }]

    cartography.intel.gcp.cloudrun.sync(
        neo4j_session, _run_client(services), SYNC_PROJECT, SYNC_PARAMS['UPDATE_TAG'],
        {**SYNC_PARAMS, 'service_labels': []}, [],
    )

    rows = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $project})-[:RESOURCE]->(s:GCPCloudRunService)
        RETURN s.id AS id, s.name AS name, s.namespace AS namespace, s.region AS region, s.url AS url,
               s.ingress AS ingress, s.latestReadyRevisionName AS revision
        """,
        project=SYNC_PROJECT,
    ).data()
    assert rows == [{
        'id': 'projects/proj-run-sync/services/web', 'name': 'web', 'namespace': '123456', 'region': 'us-central1',
        'url': 'https://web-abc-uc.a.run.app', 'ingress': 'all', 'revision': 'web-00001',
    }]
