import cartography.intel.gcp.cloudfunction
import tests.data.gcp.function
from cartography.util import run_analysis_job

TEST_PROJECT_NUMBER = 'abcd12345'
TEST_UPDATE_TAG = 123456789
TEST_REGION = 'us-east-1a'
TEST_FUNCTION_ID = 'function123'

TEST_WORKSPACE_ID = '1223344'
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


def test_load_cloud_functions(neo4j_session):
    data = tests.data.gcp.function.CLOUD_FUNCTION
    cartography.intel.gcp.cloudfunction.load_functions(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "function123",
        "function456",
    }

    nodes = neo4j_session.run(
        """
            MATCH (f:GCPFunction) RETURN f.id;
        """,
    )

    actual_nodes = {n['f.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_function_relationships(neo4j_session):
    # CREATE TEST GCP PROJECT
    neo4j_session.run(
        """
        MERGE (gcp:GCPProject{id: $PROJECT_NUMBER})
        ON CREATE SET gcp.firstseen = timestamp()
        SET gcp.lastupdated = $UPDATE_TAG
        """,
        PROJECT_NUMBER=TEST_PROJECT_NUMBER,
        UPDATE_TAG=TEST_UPDATE_TAG,
    )

    # LOAD GCP FUNCTIONS
    data = tests.data.gcp.function.CLOUD_FUNCTION
    cartography.intel.gcp.cloudfunction.load_functions(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, "function123"),
        (TEST_PROJECT_NUMBER, "function456"),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GCPFunction) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_cloud_function(neo4j_session):
    cloudanix_workspace_to_gcp_project(neo4j_session)
    data = tests.data.gcp.function.CLOUD_FUNCTION
    cartography.intel.gcp.cloudfunction.load_functions(neo4j_session, data, TEST_PROJECT_NUMBER, TEST_UPDATE_TAG)
    bindings_data = tests.data.gcp.function.FUNCTION_POLICY_BINDINGS

    cartography.intel.gcp.cloudfunction.attach_function_to_binding(neo4j_session, TEST_FUNCTION_ID, bindings_data, TEST_UPDATE_TAG)

    query1 = """
    MATCH (function:GCPFunction)<-[:RESOURCE]-(:GCPProject{id: $GCP_PROJECT_ID})<-[:OWNER]-(:GCPOrganization{id:$GCP_ORGANIZATION_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID}) \nWHERE function.exposed_internet=true
    RETURN function.id,function.exposed_internet,function.exposed_internet_type
    """
    run_analysis_job('gcp_cloud_function_analysis.json', neo4j_session, common_job_parameters)

    objects1 = neo4j_session.run(query1, GCP_PROJECT_ID=TEST_PROJECT_NUMBER, WORKSPACE_ID=TEST_WORKSPACE_ID)

    actual_nodes = {
        (
            o['function.id'],
            o['function.exposed_internet'],
            ",".join(o['function.exposed_internet_type']),

        ) for o in objects1

    }

    expected_nodes = {

        (
            'function123',
            True,
            'allUsers,allAuthenticatedUsers',
        ),

    }

    assert actual_nodes == expected_nodes


EXPOSURE_PROJECT_ID = 'proj-fn-exposure'
EXPOSURE_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG,
    'WORKSPACE_ID': 'ws-fn-exposure',
    'GCP_ORGANIZATION_ID': 'org-fn-exposure',
    'GCP_PROJECT_ID': EXPOSURE_PROJECT_ID,
}
INVOKER = 'roles/cloudfunctions.invoker'


def _seed_functions(neo4j_session, functions):
    # Properties as load_functions / attach_function_to_binding write them; absent keys stay unset.
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $workspace_id})-[:OWNER]->(o:GCPOrganization{id: $org_id})
        MERGE (o)-[:OWNER]->(p:GCPProject{id: $project_id})
        WITH p
        UNWIND $functions AS f
        MERGE (p)-[:RESOURCE]->(fn:GCPFunction{id: f.id})
        SET fn.ingressSettings = f.ingress, fn.https_trigger_url = f.url,
            fn.event_trigger_type = f.event, fn.environment = f.env
        WITH fn, f
        UNWIND f.bindings AS b
        MERGE (fn)-[:ATTACHED_BINDING]->(:GCPBinding{id: f.id + '/' + b.role, role: b.role, members: b.members})
        """,
        workspace_id=EXPOSURE_JOB_PARAMETERS['WORKSPACE_ID'], org_id=EXPOSURE_JOB_PARAMETERS['GCP_ORGANIZATION_ID'],
        project_id=EXPOSURE_PROJECT_ID, functions=functions,
    )


def test_function_public_only_when_reachable_and_invokable_by_anyone(neo4j_session):
    http = 'https://fn.example'
    all_users = [{'role': INVOKER, 'members': ['allUsers']}]
    _seed_functions(
        neo4j_session, [
            {'id': 'fn-http-open', 'ingress': 'ALLOW_ALL', 'url': http, 'bindings': all_users},
            {
                'id': 'fn-run-invoker-authenticated', 'ingress': 'ALLOW_ALL', 'url': http,
                'bindings': [{'role': 'roles/run.invoker', 'members': ['allAuthenticatedUsers', 'user:a@x.com']}],
            },
            # External load balancers are not resolved: a GCLB front door may be public, keep it.
            {'id': 'fn-gclb', 'ingress': 'ALLOW_INTERNAL_AND_GCLB', 'url': http, 'bindings': all_users},
            {'id': 'fn-internal-only', 'ingress': 'ALLOW_INTERNAL_ONLY', 'url': http, 'bindings': all_users},
            # Gen 1 event function: no URL, nothing on the internet can invoke it.
            {
                'id': 'fn-event', 'ingress': 'ALLOW_ALL', 'event': 'google.pubsub.topic.publish', 'env': 'GEN_1',
                'bindings': all_users,
            },
            # Gen 2 functions are Cloud Run services with their own URL, even when event-triggered.
            {
                'id': 'fn-event-gen2', 'ingress': 'ALLOW_ALL', 'event': 'google.pubsub.topic.publish', 'env': 'GEN_2',
                'bindings': all_users,
            },
            {
                'id': 'fn-viewer-only', 'ingress': 'ALLOW_ALL', 'url': http,
                'bindings': [{'role': 'roles/cloudfunctions.viewer', 'members': ['allUsers']}],
            },
            # Custom roles are not resolved and may carry the invoke permission.
            {
                'id': 'fn-custom-role', 'ingress': 'ALLOW_ALL', 'url': http,
                'bindings': [{'role': 'projects/p/roles/fnCaller', 'members': ['allUsers']}],
            },
            {
                'id': 'fn-private-binding', 'ingress': 'ALLOW_ALL', 'url': http,
                'bindings': [{'role': INVOKER, 'members': ['serviceAccount:sa@p.iam.gserviceaccount.com']}],
            },
            # Synced before trigger fields and ingress were stored: no evidence to narrow, stays public.
            {'id': 'fn-legacy', 'bindings': all_users},
        ],
    )

    run_analysis_job('gcp_cloud_function_analysis.json', neo4j_session, EXPOSURE_JOB_PARAMETERS)

    nodes = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $project_id})-[:RESOURCE]->(fn:GCPFunction{exposed_internet: true})
        RETURN fn.id AS id, fn.exposed_internet_type AS types
        """,
        project_id=EXPOSURE_PROJECT_ID,
    )
    assert {n['id']: sorted(n['types']) for n in nodes} == {
        'fn-http-open': ['allUsers'],
        'fn-run-invoker-authenticated': ['allAuthenticatedUsers'],
        'fn-gclb': ['allUsers'],
        'fn-event-gen2': ['allUsers'],
        'fn-custom-role': ['allUsers'],
        'fn-legacy': ['allUsers'],
    }
