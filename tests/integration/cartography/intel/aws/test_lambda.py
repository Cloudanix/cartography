import cartography.intel.aws.lambda_function
import tests.data.aws.lambda_function
from cartography.util import run_analysis_job

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-west-2'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = 123


def test_load_lambda_functions(neo4j_session):
    data = tests.data.aws.lambda_function.LIST_LAMBDA_FUNCTIONS

    cartography.intel.aws.lambda_function.load_lambda_functions(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-1",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-2",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-3",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-4",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-5",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-6",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-7",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-8",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-9",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-10",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AWSLambda) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_lambda_relationships(neo4j_session):
    # Create Test AWSAccount
    neo4j_session.run(
        """
        MERGE (aws:AWSAccount{id: $aws_account_id})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        aws_account_id=TEST_ACCOUNT_ID,
        aws_update_tag=TEST_UPDATE_TAG,
    )

    # Load Test Lambda Functions
    data = tests.data.aws.lambda_function.LIST_LAMBDA_FUNCTIONS

    cartography.intel.aws.lambda_function.load_lambda_functions(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-1"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-2"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-3"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-4"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-5"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-6"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-7"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-8"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-9"),
        (TEST_ACCOUNT_ID, "arn:aws:lambda:us-west-2:000000000000:function:sample-function-10"),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:AWSAccount)-[:RESOURCE]->(n2:AWSLambda) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected_nodes


def test_load_lambda_function_aliases(neo4j_session):
    data = tests.data.aws.lambda_function.LIST_LAMBDA_FUNCTION_ALIASES

    cartography.intel.aws.lambda_function._load_lambda_function_aliases(
        neo4j_session,
        data,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-3:LIVE",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-9:LIVE",
        "arn:aws:lambda:us-west-2:000000000000:function:sample-function-10:LIVE",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AWSLambdaFunctionAlias) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_lambda_function_aliases_relationships(neo4j_session):
    # Create Test Lambda Function
    data = tests.data.aws.lambda_function.LIST_LAMBDA_FUNCTIONS

    cartography.intel.aws.lambda_function.load_lambda_functions(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    aliases = tests.data.aws.lambda_function.LIST_LAMBDA_FUNCTION_ALIASES

    cartography.intel.aws.lambda_function._load_lambda_function_aliases(
        neo4j_session,
        aliases,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-3",
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-3:LIVE",
        ),
        (
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-9",
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-9:LIVE",
        ),
        (
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-10",
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-10:LIVE",
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:AWSLambda)-[:KNOWN_AS]->(n2:AWSLambdaFunctionAlias) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected_nodes


def test_load_lambda_event_source_mappings(neo4j_session):
    data = tests.data.aws.lambda_function.LIST_EVENT_SOURCE_MAPPINGS

    cartography.intel.aws.lambda_function._load_lambda_event_source_mappings(
        neo4j_session,
        data,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {'arn:aws:sqs:us-west-2:123456789012:mySQSqueue'}

    nodes = neo4j_session.run(
        """
        MATCH (r:AWSLambdaEventSourceMapping) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def test_load_lambda_event_source_mappings_relationships(neo4j_session):
    # Create Test Lambda Function
    data = tests.data.aws.lambda_function.LIST_LAMBDA_FUNCTIONS

    cartography.intel.aws.lambda_function.load_lambda_functions(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    esm = tests.data.aws.lambda_function.LIST_EVENT_SOURCE_MAPPINGS

    cartography.intel.aws.lambda_function._load_lambda_event_source_mappings(
        neo4j_session,
        esm,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            'arn:aws:lambda:us-west-2:000000000000:function:sample-function-8',
            'arn:aws:sqs:us-west-2:123456789012:mySQSqueue',
        ),
        (
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-7",
            "arn:aws:sqs:us-west-2:123456789012:mySQSqueue",
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:AWSLambda)-[:RESOURCE]->(n2:AWSLambdaEventSourceMapping) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }
    assert actual == expected_nodes


def test_load_lambda_layers(neo4j_session):
    data = tests.data.aws.lambda_function.LIST_LAYERS

    cartography.intel.aws.lambda_function._load_lambda_layers(
        neo4j_session,
        data,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "arn:aws:lambda:us-east-2:123456789012:layer:my-layer-1",
        "arn:aws:lambda:us-east-2:123456789012:layer:my-layer-2",
        "arn:aws:lambda:us-east-2:123456789012:layer:my-layer-3",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:AWSLambdaLayer) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_lambda_layers_relationships(neo4j_session):
    # Create Test Lambda Function
    data = tests.data.aws.lambda_function.LIST_LAMBDA_FUNCTIONS

    cartography.intel.aws.lambda_function.load_lambda_functions(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    layers = tests.data.aws.lambda_function.LIST_LAYERS

    cartography.intel.aws.lambda_function._load_lambda_layers(
        neo4j_session,
        layers,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-2",
            "arn:aws:lambda:us-east-2:123456789012:layer:my-layer-1",
        ),
        (
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-3",
            "arn:aws:lambda:us-east-2:123456789012:layer:my-layer-2",
        ),
        (
            "arn:aws:lambda:us-west-2:000000000000:function:sample-function-4",
            "arn:aws:lambda:us-east-2:123456789012:layer:my-layer-3",
        ),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:AWSLambda)-[:HAS]->(n2:AWSLambdaLayer) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected_nodes


EXPOSURE_WORKSPACE_ID = 'ws-lambda-exposure'
EXPOSURE_ORG_ID = 'o-lambda-exposure'
EXPOSURE_ACCOUNT_ID = '111111111111'
OTHER_WORKSPACE_ID = 'ws-other'
EXPOSURE_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG + 1,
    'AWS_ID': EXPOSURE_ACCOUNT_ID,
    'ORGANIZATION_ID': EXPOSURE_ORG_ID,
    'WORKSPACE_ID': EXPOSURE_WORKSPACE_ID,
    'LIMIT_SIZE': 100,
}


def _seed_exposure_account(neo4j_session, workspace_id, org_id, account_id):
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $workspace_id})-[:OWNER]->(o:AWSOrganization{id: $org_id})
        MERGE (o)-[:OWNER]->(:AWSAccount{id: $account_id})
        """,
        workspace_id=workspace_id, org_id=org_id, account_id=account_id,
    )


def _seed_rest_apis(neo4j_session, account_id, apis):
    neo4j_session.run(
        """
        UNWIND $apis AS a
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (aa)-[:RESOURCE]->(:APIGatewayRestAPI{id: a.id, endpoint_conf_types: a.types})
        """,
        account_id=account_id, apis=apis,
    )


def _seed_lambdas(neo4j_session, lambdas):
    # Properties exactly as load_lambda_functions writes them; absent keys stay unset.
    neo4j_session.run(
        """
        UNWIND $lambdas AS l
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (aa)-[:RESOURCE]->(lf:AWSLambda{id: l.arn})
        SET lf.arn = l.arn, lf.name = l.arn, lf.vpc_id = l.vpc_id,
            lf.public_trigger_sources = l.public_trigger_sources,
            lf.apigateway_source_api_ids = l.apigateway_source_api_ids
        """,
        account_id=EXPOSURE_ACCOUNT_ID, lambdas=lambdas,
    )


def _exposed_lambdas(neo4j_session):
    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(lf:AWSLambda{exposed_internet: true})
        RETURN lf.id AS id, lf.exposed_internet_type AS types
        """,
        account_id=EXPOSURE_ACCOUNT_ID,
    )
    return {n['id']: sorted(n['types']) for n in nodes}


def test_lambda_api_gateway_trigger_is_public_only_through_a_public_api(neo4j_session):
    _seed_exposure_account(neo4j_session, EXPOSURE_WORKSPACE_ID, EXPOSURE_ORG_ID, EXPOSURE_ACCOUNT_ID)
    _seed_exposure_account(neo4j_session, OTHER_WORKSPACE_ID, 'o-other', '222222222222')
    _seed_rest_apis(
        neo4j_session, EXPOSURE_ACCOUNT_ID, [
            {'id': 'privapi', 'types': ['PRIVATE']},
            {'id': 'pubapi', 'types': ['REGIONAL']},
            {'id': 'edgeapi', 'types': ['EDGE']},
        ],
    )
    # A PRIVATE API in another tenant's workspace must not resolve for this workspace's Lambdas.
    _seed_rest_apis(neo4j_session, '222222222222', [{'id': 'otherws', 'types': ['PRIVATE']}])
    apigw = ['apigateway']
    _seed_lambdas(
        neo4j_session, [
            {'arn': 'lf-private-api', 'public_trigger_sources': apigw, 'apigateway_source_api_ids': ['privapi']},
            {'arn': 'lf-public-api', 'public_trigger_sources': apigw, 'apigateway_source_api_ids': ['pubapi']},
            {'arn': 'lf-edge-api', 'public_trigger_sources': apigw, 'apigateway_source_api_ids': ['edgeapi']},
            {
                'arn': 'lf-private-and-public', 'public_trigger_sources': apigw,
                'apigateway_source_api_ids': ['privapi', 'pubapi'],
            },
            {'arn': 'lf-any-api', 'public_trigger_sources': apigw, 'apigateway_source_api_ids': ['*']},
            {
                'arn': 'lf-private-and-any', 'public_trigger_sources': apigw,
                'apigateway_source_api_ids': ['*', 'privapi'],
            },
            # Cross-account API, or an HTTP API (never private): not in the graph, stays public.
            {'arn': 'lf-unknown-api', 'public_trigger_sources': apigw, 'apigateway_source_api_ids': ['notingraph']},
            {
                'arn': 'lf-other-workspace-api', 'public_trigger_sources': apigw,
                'apigateway_source_api_ids': ['otherws'],
            },
            # Synced before apigateway_source_api_ids existed: no evidence to narrow, stays public.
            {'arn': 'lf-no-ids', 'public_trigger_sources': apigw},
            {'arn': 'lf-no-trigger', 'public_trigger_sources': [], 'vpc_id': 'vpc-1'},
        ],
    )

    run_analysis_job('aws_apigateway_asset_exposure.json', neo4j_session, EXPOSURE_JOB_PARAMETERS)
    run_analysis_job('aws_lambda_function_asset_exposure.json', neo4j_session, EXPOSURE_JOB_PARAMETERS)

    assert _exposed_lambdas(neo4j_session) == {
        'lf-public-api': ['apigateway_trigger'],
        'lf-edge-api': ['apigateway_trigger'],
        'lf-private-and-public': ['apigateway_trigger'],
        'lf-any-api': ['apigateway_trigger'],
        'lf-private-and-any': ['apigateway_trigger'],
        'lf-unknown-api': ['apigateway_trigger'],
        'lf-other-workspace-api': ['apigateway_trigger'],
        'lf-no-ids': ['apigateway_trigger'],
    }
