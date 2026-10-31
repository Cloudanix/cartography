import cartography.intel.aws.apigateway
import tests.data.aws.apigateway
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_exposure_test_account

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'eu-west-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = '12345'


def test_load_apigateway_rest_apis(neo4j_session):
    data = tests.data.aws.apigateway.GET_REST_APIS
    cartography.intel.aws.apigateway.load_apigateway_rest_apis(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "test-001",
        "test-002",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:APIGatewayRestAPI) RETURN r.id;
        """,
    )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_apigateway_rest_apis_relationships(neo4j_session):
    # Create Test AWSAccount
    neo4j_session.run(
        """
            MERGE (aws:AWSAccount{id: $aws_account_id})<-[:OWNER]-(:CloudanixWorkspace{id: $workspace_id})
            ON CREATE SET aws.firstseen = timestamp()
            SET aws.lastupdated = $aws_update_tag
            """,
        aws_account_id=TEST_ACCOUNT_ID,
        aws_update_tag=TEST_UPDATE_TAG,
        workspace_id=TEST_WORKSPACE_ID,
    )

    # Load Test API Gateway REST APIs
    data = tests.data.aws.apigateway.GET_REST_APIS
    cartography.intel.aws.apigateway.load_apigateway_rest_apis(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )
    expected = {
        (TEST_ACCOUNT_ID, 'test-001'),
        (TEST_ACCOUNT_ID, 'test-002'),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:AWSAccount)-[:RESOURCE]->(n2:APIGatewayRestAPI) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_load_apigateway_stages(neo4j_session):
    data = tests.data.aws.apigateway.GET_STAGES
    cartography.intel.aws.apigateway._load_apigateway_stages(
        neo4j_session,
        data,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'arn:aws:apigateway:us-east-1::/restapis/test-001/stages/Cartography-testing-infra',
        'arn:aws:apigateway:us-east-1::/restapis/test-002/stages/Cartography-testing-unit',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:APIGatewayStage) RETURN r.id;
        """,
    )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_apigateway_stages_relationships(neo4j_session):
    # Load Test REST API
    data_rest_api = tests.data.aws.apigateway.GET_REST_APIS
    cartography.intel.aws.apigateway.load_apigateway_rest_apis(
        neo4j_session,
        data_rest_api,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    # Load test API Gateway Stages
    data_stages = tests.data.aws.apigateway.GET_STAGES
    cartography.intel.aws.apigateway._load_apigateway_stages(
        neo4j_session,
        data_stages,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            'test-001',
            'arn:aws:apigateway:us-east-1::/restapis/test-001/stages/Cartography-testing-infra',
        ),
        (
            'test-002',
            'arn:aws:apigateway:us-east-1::/restapis/test-002/stages/Cartography-testing-unit',
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:APIGatewayRestAPI)-[:ASSOCIATED_WITH]->(n2:APIGatewayStage) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_load_apigateway_certificates(neo4j_session):
    data = tests.data.aws.apigateway.GET_CERTIFICATES
    cartography.intel.aws.apigateway._load_apigateway_certificates(
        neo4j_session,
        data,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        'arn:aws:apigateway:us-east-1::/clientcertificates/cert-002',
        'arn:aws:apigateway:us-east-1::/clientcertificates/cert-001',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:APIGatewayClientCertificate) RETURN r.id;
        """,
    )
    actual_nodes = {n['r.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def test_load_apigateway_certificates_relationships(neo4j_session):
    # Load test API Gateway Stages
    data_stages = tests.data.aws.apigateway.GET_STAGES
    cartography.intel.aws.apigateway._load_apigateway_stages(
        neo4j_session,
        data_stages,
        TEST_UPDATE_TAG,
    )

    # Load test Client Certificates
    data_certificates = tests.data.aws.apigateway.GET_CERTIFICATES
    cartography.intel.aws.apigateway._load_apigateway_certificates(
        neo4j_session,
        data_certificates,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            'arn:aws:apigateway:us-east-1::/restapis/test-001/stages/Cartography-testing-infra',
            'cert-001',
        ),
        (
            'arn:aws:apigateway:us-east-1::/restapis/test-002/stages/Cartography-testing-unit',
            'cert-002',
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:APIGatewayStage)-[:HAS_CERTIFICATE]->(n2:APIGatewayClientCertificate) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }
    assert actual == expected


def test_load_apigateway_resources(neo4j_session):
    data = tests.data.aws.apigateway.GET_RESOURCES
    cartography.intel.aws.apigateway._load_apigateway_resources(
        neo4j_session,
        data,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "3kzxbg5sa2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:APIGatewayResource) RETURN r.id;
        """,
    )
    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_apigateway_resources_relationships(neo4j_session):
    # Load Test REST API
    data_rest_api = tests.data.aws.apigateway.GET_REST_APIS
    cartography.intel.aws.apigateway.load_apigateway_rest_apis(
        neo4j_session,
        data_rest_api,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    # Load test API Gateway Resource resources
    data_resources = tests.data.aws.apigateway.GET_RESOURCES
    cartography.intel.aws.apigateway._load_apigateway_resources(
        neo4j_session,
        data_resources,
        TEST_UPDATE_TAG,
    )

    expected = {
        (
            'test-001', '3kzxbg5sa2',
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:APIGatewayRestAPI)-[:RESOURCE]->(n2:APIGatewayResource) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }
    assert actual == expected


def test_load_apigateway_client_certificates_data(neo4j_session):
    _ensure_local_neo4j_has_test_apigateway_client_certificates_data(neo4j_session)
    expected_nodes = {
        "arn:aws:apigateway:us-east-1::/clientcertificates/cert-002",
        "arn:aws:apigateway:us-east-1::/clientcertificates/cert-001",
    }
    nodes = neo4j_session.run(
        """
        MATCH (n:APIGatewayClientCertificate) RETURN n.id;
        """,
    )
    actual_nodes = {n['n.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def _ensure_local_neo4j_has_test_apigateway_client_certificates_data(neo4j_session):
    cartography.intel.aws.apigateway.load_client_certificates(
        neo4j_session,
        tests.data.aws.apigateway.GET_CERTIFICATES,
        '123456789012',
        TEST_UPDATE_TAG,
    )


def test_apigateway_analysis(neo4j_session):
    data = tests.data.aws.apigateway.GET_REST_APIS
    cartography.intel.aws.apigateway.load_apigateway_rest_apis(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    common_job_parameters = {
        "UPDATE_TAG": TEST_UPDATE_TAG + 1,
        "WORKSPACE_ID": TEST_WORKSPACE_ID,
        "AWS_ID": TEST_ACCOUNT_ID,
    }

    run_analysis_job('aws_apigateway_asset_exposure.json', neo4j_session, common_job_parameters)

    expected = {
        ('test-001', 'endpoint_type'),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n:APIGatewayRestAPI{exposed_internet: true}) RETURN n.id, n.exposed_internet_type;
        """,
    )
    actual = {
        (r['n.id'], ",".join(r['n.exposed_internet_type'])) for r in result
    }

    assert actual == expected


POLICY_ACCOUNT_ID = '444455556666'
POLICY_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG + 1,
    'AWS_ID': POLICY_ACCOUNT_ID,
    'ORGANIZATION_ID': 'o-apigw-policy',
    'WORKSPACE_ID': 'ws-apigw-policy',
    'LIMIT_SIZE': 100,
}
# iterationsize of the job's resets; GraphStatement uses it as LIMIT_SIZE whatever the parameters say.
RESET_BATCH = 100
OPEN_POLICY = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", '
    '"Action": "execute-api:Invoke", "Resource": "execute-api:/*"}]}'
)
VPCE_POLICY = (
    '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", '
    '"Action": "execute-api:Invoke", "Resource": "execute-api:/*", '
    '"Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]}'
)


def test_apigateway_exposure_honours_resource_policy(neo4j_session):
    create_exposure_test_account(
        neo4j_session, POLICY_JOB_PARAMETERS['WORKSPACE_ID'], POLICY_JOB_PARAMETERS['ORGANIZATION_ID'],
        POLICY_ACCOUNT_ID,
    )
    apis = {
        'gw-regional-open': (['REGIONAL'], OPEN_POLICY),
        # Principal * but only through one VPC endpoint: nothing on the internet can invoke it.
        'gw-regional-vpce': (['REGIONAL'], VPCE_POLICY),
        # No policy, or one we cannot parse: stays public (fail-safe).
        'gw-regional-none': (['REGIONAL'], None),
        'gw-edge-unparseable': (['EDGE'], '{not json'),
        # A PRIVATE API is reachable only through VPC endpoints, whatever its policy says.
        'gw-private-open': (['PRIVATE'], OPEN_POLICY),
        # Restricted on an earlier sync, policy since deleted.
        'gw-policy-removed': (['REGIONAL'], None),
    }
    cartography.intel.aws.apigateway.load_apigateway_rest_apis(
        neo4j_session,
        [
            {
                'id': api_id, 'name': f'name-of-{api_id}', 'region': TEST_REGION,
                'endpointConfiguration': {'types': types},
            }
            for api_id, (types, _) in apis.items()
        ],
        POLICY_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )
    neo4j_session.run(
        """
        MATCH (api:APIGatewayRestAPI{id: 'gw-policy-removed'}) SET api.policy_internet_accessible = false
        WITH api
        MATCH (open:APIGatewayRestAPI{id: 'gw-regional-open'})
        UNWIND $resources AS res
        MERGE (open)-[:RESOURCE]->(r:APIGatewayResource{id: res})
        SET r.anonymous_access = CASE WHEN res = 'gw-res-stale' THEN true END
        """,
        # The stale resource sits between more than a batch of clean ones on each side, so a reset
        # that stops at the first batch with no updates never reaches it.
        resources=[f'gw-res-clean-{i}' for i in range(RESET_BATCH + 1)] + ['gw-res-stale'] +
        [f'gw-res-clean-after-{i}' for i in range(RESET_BATCH + 1)],
    )

    cartography.intel.aws.apigateway.load_rest_api_details(
        neo4j_session,
        [(api_id, [], [], [], policy, TEST_REGION) for api_id, (_, policy) in apis.items()],
        POLICY_ACCOUNT_ID,
        TEST_UPDATE_TAG,
        POLICY_JOB_PARAMETERS,
    )
    run_analysis_job('aws_apigateway_asset_exposure.json', neo4j_session, POLICY_JOB_PARAMETERS)

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(api:APIGatewayRestAPI)
        OPTIONAL MATCH (api)-[:RESOURCE]->(res:APIGatewayResource)
        WITH api, collect(res) AS resources
        RETURN api.id AS id, api.exposed_internet AS exposed, api.anonymous_access AS anonymous,
               [r IN resources WHERE r.anonymous_access OR r.exposed_internet | r.id] AS public_resources
        """,
        account_id=POLICY_ACCOUNT_ID,
    )
    assert {n['id']: (n['exposed'], n['anonymous'], n['public_resources']) for n in nodes} == {
        'gw-regional-open': (True, False, []),
        'gw-regional-vpce': (None, False, []),
        'gw-regional-none': (True, False, []),
        'gw-edge-unparseable': (True, False, []),
        'gw-private-open': (None, False, []),
        'gw-policy-removed': (True, False, []),
    }
