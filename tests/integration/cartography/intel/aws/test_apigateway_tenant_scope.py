"""API Gateway nodes are keyed per tenant, and stages, resources and certificates link only to the syncing account's
REST APIs and stages."""
from importlib.resources import read_text

from cartography.graph.job import GraphJob
from cartography.intel.aws import apigateway
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
OWN, OTHER = 'apigw-own', 'apigw-other'


def _api_arn(api_id, region=REGION):
    return f'arn:aws:apigateway:{region}::/restapis/{api_id}'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, 'apigw-ws-own', 'apigw-org-own', OWN)
    create_test_org_account(neo4j_session, 'apigw-ws-other', 'apigw-org-other', OTHER)
    # Another customer's REST API and stage, using the same client certificate id.
    neo4j_session.run(
        """
        MATCH (other:AWSAccount{id: $other})
        MERGE (other)-[:RESOURCE]->(api:APIGatewayRestAPI{id: $api})
        MERGE (api)-[:ASSOCIATED_WITH]->(:APIGatewayStage{id: 'stage-other', clientcertificateid: 'cert-x'})
        """,
        other=OTHER, api=_api_arn('api-other'),
    )
    apigateway.load_apigateway_rest_apis(neo4j_session, [{'id': 'api-own', 'region': REGION}], OWN, TAG)


def _stage(api_id, name, region=REGION):
    return {'apiId': api_id, 'region': region, 'stageName': name, 'createdDate': 'd', 'clientCertificateId': 'cert-x'}


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
    assert {(r['api'], r['s']) for r in stages} == {(_api_arn('api-own'), 'own'), (_api_arn('api-other'), None)}
    resources = neo4j_session.run(
        "MATCH (api:APIGatewayRestAPI)-[:RESOURCE]->(r:APIGatewayResource) RETURN api.id AS api, r.id AS r",
    )
    assert {(r['api'], r['r']) for r in resources} == {
        (_api_arn('api-own'), _api_arn('api-own') + '/resources/res-own'),
    }
    certified = neo4j_session.run(
        "MATCH (api:APIGatewayRestAPI)-[:ASSOCIATED_WITH]->(s)-[:HAS_CERTIFICATE]->(:APIGatewayClientCertificate) "
        "RETURN api.id AS api",
    )
    assert [r['api'] for r in certified] == [_api_arn('api-own')]


# Two customers whose REST APIs share the short id 'ak-api' (and resource id 'ak-res'). AWS makes a REST API id
# unique within a region (it is the execute-api host name), so the accounts are in different regions.
TENANTS = {
    'ak-a1': ('ak-w1', 'us-east-1', 'cert-a'),
    'ak-b1': ('ak-w2', 'eu-west-1', 'cert-b'),
}


def _load_tenant(neo4j_session, account, tag):
    workspace, region, cert = TENANTS[account]
    apigateway.load_apigateway_rest_apis(
        neo4j_session, [{'id': 'ak-api', 'name': f'api-of-{account}', 'region': region}], account, tag,
    )
    apigateway.load_rest_api_details(
        neo4j_session,
        [(
            'ak-api',
            [{'stageName': f'stage-{account}', 'createdDate': 'd', 'clientCertificateId': cert}],
            [{'clientCertificateId': cert, 'arn': f'arn:aws:apigateway:{region}::/clientcertificates/{cert}'}],
            [{'id': 'ak-res', 'path': f'/{account}'}],
            None,
            region,
        )],
        account, tag,
        {'WORKSPACE_ID': workspace, 'ORGANIZATION_ID': f'{workspace}/o', 'AWS_ID': account, 'UPDATE_TAG': tag},
    )


def _run_cleanup(neo4j_session, account, tag):
    workspace = TENANTS[account][0]
    GraphJob.run_from_json(
        neo4j_session,
        read_text('cartography.data.jobs.cleanup', 'aws_import_apigateway_cleanup.json'),
        {
            'WORKSPACE_ID': workspace, 'ORGANIZATION_ID': f'{workspace}/o', 'AWS_ID': account,
            'UPDATE_TAG': tag, 'LIMIT_SIZE': 100,
        },
    )


def _graph(neo4j_session):
    return {
        tuple(r.values()) for r in neo4j_session.run(
            """
            MATCH (a:AWSAccount)-[:RESOURCE]->(api:APIGatewayRestAPI) WHERE a.id STARTS WITH 'ak-'
            OPTIONAL MATCH (api)-[:ASSOCIATED_WITH]->(s:APIGatewayStage)
            OPTIONAL MATCH (s)-[:HAS_CERTIFICATE]->(c:APIGatewayClientCertificate)
            OPTIONAL MATCH (api)-[:RESOURCE]->(r:APIGatewayResource)
            RETURN a.id, api.id, api.rest_api_id, api.name, s.stagename, c.client_certificate_id, r.id,
                r.resource_id, r.path
            """,
        )
    }


def test_same_short_ids_in_two_tenants_are_separate_nodes(neo4j_session):
    for account, (workspace, _, _) in TENANTS.items():
        create_test_org_account(neo4j_session, workspace, f'{workspace}/o', account)
        _load_tenant(neo4j_session, account, TAG)

    a_api, b_api = _api_arn('ak-api', 'us-east-1'), _api_arn('ak-api', 'eu-west-1')
    assert _graph(neo4j_session) == {
        (
            'ak-a1', a_api, 'ak-api', 'api-of-ak-a1', 'stage-ak-a1', 'cert-a', a_api + '/resources/ak-res',
            'ak-res', '/ak-a1',
        ),
        (
            'ak-b1', b_api, 'ak-api', 'api-of-ak-b1', 'stage-ak-b1', 'cert-b', b_api + '/resources/ak-res',
            'ak-res', '/ak-b1',
        ),
    }


def test_old_short_id_nodes_are_removed_on_the_next_sync(neo4j_session):
    # The graph as the short-id loader left it for ak-a1: REST API 'ak-api' and resource 'ak-res' keyed on their
    # short ids, the API linked to the stage (whose id was already its ARN, so the new sync reuses it).
    old, new = 1, TAG + 1
    for account, (workspace, _, _) in TENANTS.items():
        create_test_org_account(neo4j_session, workspace, f'{workspace}/o', account)
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: 'ak-a1'})
        MERGE (a)-[:RESOURCE{lastupdated: $old}]->(api:APIGatewayRestAPI{id: 'ak-api'}) SET api.lastupdated = $old
        MERGE (api)-[:RESOURCE{lastupdated: $old}]->(r:APIGatewayResource{id: 'ak-res'}) SET r.lastupdated = $old
        MERGE (s:APIGatewayStage{id: $stage}) SET s.lastupdated = $old
        MERGE (api)-[:ASSOCIATED_WITH{lastupdated: $old}]->(s)
        """,
        old=old, stage=_api_arn('ak-api') + '/stages/stage-ak-a1',
    )
    _load_tenant(neo4j_session, 'ak-b1', TAG)

    _load_tenant(neo4j_session, 'ak-a1', new)
    _run_cleanup(neo4j_session, 'ak-a1', new)

    assert neo4j_session.run(
        "MATCH (n) WHERE (n:APIGatewayRestAPI OR n:APIGatewayResource) AND n.id STARTS WITH 'ak-' RETURN count(n) AS c",
    ).single()['c'] == 0
    a_api, b_api = _api_arn('ak-api', 'us-east-1'), _api_arn('ak-api', 'eu-west-1')
    assert {(r[0], r[1], r[4]) for r in _graph(neo4j_session)} == {
        ('ak-a1', a_api, 'stage-ak-a1'), ('ak-b1', b_api, 'stage-ak-b1'),
    }
    assert neo4j_session.run(
        "MATCH (:APIGatewayStage{id: $stage})<-[:ASSOCIATED_WITH]-(api) RETURN collect(api.id) AS apis",
        stage=_api_arn('ak-api') + '/stages/stage-ak-a1',
    ).single()['apis'] == [a_api]
