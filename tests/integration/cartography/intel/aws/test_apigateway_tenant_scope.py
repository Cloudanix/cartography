"""API Gateway stages, resources and certificates link only to the syncing account's REST APIs and stages."""
from cartography.intel.aws import apigateway
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
OWN, OTHER = 'apigw-own', 'apigw-other'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, 'apigw-ws-own', 'apigw-org-own', OWN)
    create_test_org_account(neo4j_session, 'apigw-ws-other', 'apigw-org-other', OTHER)
    # Another customer's REST API and stage, using the same client certificate id.
    neo4j_session.run(
        """
        MATCH (other:AWSAccount{id: $other})
        MERGE (other)-[:RESOURCE]->(api:APIGatewayRestAPI{id: 'api-other'})
        MERGE (api)-[:ASSOCIATED_WITH]->(:APIGatewayStage{id: 'stage-other', clientcertificateid: 'cert-x'})
        """,
        other=OTHER,
    )
    apigateway.load_apigateway_rest_apis(neo4j_session, [{'id': 'api-own', 'region': REGION}], OWN, TAG)


def _stage(api_id, name):
    return {'apiId': api_id, 'region': REGION, 'stageName': name, 'createdDate': 'd', 'clientCertificateId': 'cert-x'}


def test_stages_resources_and_certificates_stay_in_the_account(neo4j_session):
    _seed(neo4j_session)

    apigateway._load_apigateway_stages(
        neo4j_session, [_stage('api-own', 'own'), _stage('api-other', 'stray')], OWN, TAG,
    )
    apigateway._load_apigateway_resources(
        neo4j_session,
        [
            {'id': 'res-own', 'apiId': 'api-own', 'region': REGION},
            {'id': 'res-stray', 'apiId': 'api-other', 'region': REGION},
        ],
        OWN, TAG,
    )
    apigateway._load_apigateway_certificates(
        neo4j_session,
        [{'arn': 'cert-arn-own', 'clientCertificateId': 'cert-x', 'apiId': 'api-own', 'region': REGION}],
        OWN, TAG,
    )

    stages = neo4j_session.run(
        "MATCH (api:APIGatewayRestAPI)-[:ASSOCIATED_WITH]->(s:APIGatewayStage) RETURN api.id AS api, s.stagename AS s",
    )
    assert {(r['api'], r['s']) for r in stages} == {('api-own', 'own'), ('api-other', None)}
    resources = neo4j_session.run(
        "MATCH (api:APIGatewayRestAPI)-[:RESOURCE]->(r:APIGatewayResource) RETURN api.id AS api, r.id AS r",
    )
    assert {(r['api'], r['r']) for r in resources} == {('api-own', 'res-own')}
    certified = neo4j_session.run(
        "MATCH (api:APIGatewayRestAPI)-[:ASSOCIATED_WITH]->(s)-[:HAS_CERTIFICATE]->(:APIGatewayClientCertificate) "
        "RETURN api.id AS api",
    )
    assert [r['api'] for r in certified] == ['api-own']
