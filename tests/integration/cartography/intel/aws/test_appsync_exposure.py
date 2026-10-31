import json

import cartography.intel.aws.appsync
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters
from tests.integration.cartography.intel.aws.test_appsync import _api

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777792'
OTHER_ACCOUNT_ID = '888888888892'


def _exposure(neo4j_session):
    rows = neo4j_session.run(
        "MATCH (n:AppSyncGraphqlApi) RETURN n.api_id AS api, n.exposed_internet AS exposed, "
        "n.exposed_internet_type AS types, n.publicContext AS context",
    )
    return {r['api']: r for r in rows}


def test_appsync_api_public_when_its_endpoint_is_global(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-appsyncx', 'o-appsyncx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-appsyncx-other', 'o-appsyncx-other', OTHER_ACCOUNT_ID)
    cartography.intel.aws.appsync.load_graphql_apis(
        neo4j_session, [
            _api(ACCOUNT_ID, 'appx-iam', wafWebAclArn='arn:waf'),
            _api(ACCOUNT_ID, 'appx-key', authenticationType='API_KEY'),
            _api(
                ACCOUNT_ID, 'appx-cognito-plus-key', authenticationType='AMAZON_COGNITO_USER_POOLS',
                additionalAuthenticationTypes=['API_KEY'],
            ),
            _api(ACCOUNT_ID, 'appx-private', visibility='PRIVATE', authenticationType='API_KEY'),
            _api(ACCOUNT_ID, 'appx-private-since', visibility='PRIVATE'),
        ], ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.appsync.load_graphql_apis(
        neo4j_session, [_api(OTHER_ACCOUNT_ID, 'appx-other')], OTHER_ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    # Was GLOBAL on an earlier sync.
    neo4j_session.run(
        "MATCH (n:AppSyncGraphqlApi{api_id: 'appx-private-since'}) "
        "SET n.exposed_internet = true, n.exposed_internet_type = ['global_endpoint'], n.publicContext = '[]'",
    )

    run_analysis_job(
        'aws_appsync_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-appsyncx', 'o-appsyncx', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    apis = _exposure(neo4j_session)
    assert {a for a, r in apis.items() if r['exposed']} == {'appx-iam', 'appx-key', 'appx-cognito-plus-key'}
    assert apis['appx-iam']['types'] == ['global_endpoint']
    assert apis['appx-key']['types'] == ['global_endpoint', 'api_key_auth']
    assert apis['appx-cognito-plus-key']['types'] == ['global_endpoint', 'api_key_auth']
    assert (apis['appx-private-since']['types'], apis['appx-private-since']['context']) == (None, None)
    # Other tenant: never evaluated by this account's run.
    assert apis['appx-other']['exposed'] is None

    context = json.loads(apis['appx-iam']['context'])[0]
    assert (context['resource'], context['resourceType']) == (
        f'arn:aws:appsync:us-east-1:{ACCOUNT_ID}:apis/appx-iam', 'aws-networking-appsync-graphqlapi',
    )
    detail = context['context'][0]
    assert (detail['authenticationType'], detail['wafWebAclArn'], detail['wafAssociated']) == (
        'AWS_IAM', 'arn:waf', True,
    )
    key_detail = json.loads(apis['appx-cognito-plus-key']['context'])[0]['context'][0]
    assert (key_detail['additionalAuthenticationTypes'], key_detail['wafAssociated']) == (['API_KEY'], False)
