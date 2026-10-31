import cartography.intel.aws.appsync
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777791'
OTHER_ACCOUNT_ID = '888888888891'


def _api(account_id, api_id, **overrides):
    # Shape of transform_graphql_apis() output.
    return {
        'arn': f'arn:aws:appsync:us-east-1:{account_id}:apis/{api_id}', 'apiId': api_id, 'name': api_id,
        'region': 'us-east-1', 'consolelink': None, 'authenticationType': 'AWS_IAM',
        'additionalAuthenticationTypes': [], 'wafWebAclArn': None, 'visibility': 'GLOBAL', 'apiType': 'GRAPHQL',
        'xrayEnabled': False, 'logFieldLogLevel': None, 'graphqlUri': None, **overrides,
    }


def test_load_graphql_apis_and_cleanup_only_this_account(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-appsync', 'o-appsync', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-appsync-other', 'o-appsync-other', OTHER_ACCOUNT_ID)
    cartography.intel.aws.appsync.load_graphql_apis(
        neo4j_session, [_api(OTHER_ACCOUNT_ID, 'appsync-other')], OTHER_ACCOUNT_ID, TEST_UPDATE_TAG - 1,
    )
    cartography.intel.aws.appsync.load_graphql_apis(
        neo4j_session, [_api(ACCOUNT_ID, 'appsync-gone')], ACCOUNT_ID, TEST_UPDATE_TAG - 1,
    )
    cartography.intel.aws.appsync.load_graphql_apis(
        neo4j_session,
        [_api(ACCOUNT_ID, 'appsync-orders', wafWebAclArn='arn:waf', additionalAuthenticationTypes=['API_KEY'])],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    cartography.intel.aws.appsync.cleanup_graphql_apis(
        neo4j_session, exposure_job_parameters('ws-appsync', 'o-appsync', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (a:AWSAccount)-[:RESOURCE]->(n:AppSyncGraphqlApi) RETURN a.id AS account, n.api_id AS api, "
        "n.waf_web_acl_arn AS waf, n.additional_authentication_types AS extra, n.visibility AS visibility",
    )
    apis = {r['api']: r for r in rows}
    assert set(apis) == {'appsync-orders', 'appsync-other'}
    assert apis['appsync-orders']['account'] == ACCOUNT_ID
    assert (apis['appsync-orders']['waf'], apis['appsync-orders']['extra']) == ('arn:waf', ['API_KEY'])
