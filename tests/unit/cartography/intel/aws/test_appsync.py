from unittest.mock import MagicMock

from botocore.exceptions import EndpointConnectionError

from cartography.intel.aws import appsync

API_ARN = 'arn:aws:appsync:us-east-1:111111111111:apis/abc123'


def _session(pages=None, error=None):
    paginator = MagicMock()
    if error:
        paginator.paginate.side_effect = error
    else:
        paginator.paginate.return_value = pages
    client = MagicMock()
    client.get_paginator.return_value = paginator
    session = MagicMock()
    session.client.return_value = client
    return session


def test_get_graphql_apis_reads_every_page():
    session = _session(pages=[{'graphqlApis': [{'arn': 'a'}]}, {'graphqlApis': [{'arn': 'b'}]}])

    assert appsync.get_graphql_apis(session, 'us-east-1') == [{'arn': 'a'}, {'arn': 'b'}]


def test_get_graphql_apis_skips_a_region_without_appsync():
    session = _session(error=EndpointConnectionError(endpoint_url='https://appsync.xx-1.amazonaws.com'))

    assert appsync.get_graphql_apis(session, 'xx-1') == []


def test_transform_graphql_apis_keeps_auth_modes_waf_and_visibility():
    apis = [
        {
            'arn': API_ARN, 'apiId': 'abc123', 'name': 'orders', 'authenticationType': 'AMAZON_COGNITO_USER_POOLS',
            'additionalAuthenticationProviders': [{'authenticationType': 'API_KEY'}, {'authenticationType': 'AWS_IAM'}],
            'wafWebAclArn': 'arn:aws:wafv2:us-east-1:111111111111:regional/webacl/acl/1', 'visibility': 'PRIVATE',
            'apiType': 'GRAPHQL', 'xrayEnabled': True, 'logConfig': {'fieldLogLevel': 'ALL'},
            'uris': {'GRAPHQL': 'https://abc123.appsync-api.us-east-1.amazonaws.com/graphql'},
        },
        # Created before private APIs existed: no visibility field, no optional settings.
        {'arn': API_ARN + 'old', 'apiId': 'old', 'name': 'legacy', 'authenticationType': 'API_KEY'},
        {'apiId': 'no-arn'},
    ]

    rows = appsync.transform_graphql_apis(apis, 'us-east-1')

    assert [r['apiId'] for r in rows] == ['abc123', 'old']
    assert rows[0]['additionalAuthenticationTypes'] == ['API_KEY', 'AWS_IAM']
    assert (rows[0]['visibility'], rows[0]['logFieldLogLevel'], rows[0]['region']) == ('PRIVATE', 'ALL', 'us-east-1')
    assert rows[0]['graphqlUri'].endswith('/graphql')
    assert rows[0]['consolelink'].startswith('https://')
    assert (rows[1]['visibility'], rows[1]['additionalAuthenticationTypes'], rows[1]['wafWebAclArn']) == (
        'GLOBAL', [], None,
    )
