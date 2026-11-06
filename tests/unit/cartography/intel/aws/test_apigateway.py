from unittest.mock import MagicMock

from botocore.exceptions import ClientError

import tests.data.aws.apigateway as test_data
from cartography.intel.aws.apigateway import add_public_custom_domains
from cartography.intel.aws.apigateway import build_apigateway_arn
from cartography.intel.aws.apigateway import get_apigateway_console_link
from cartography.intel.aws.apigateway import parse_policy
from cartography.intel.aws.apigateway import transform_client_certificates
from cartography.intel.aws.apigateway import transform_rest_api_client_certificate


def test_build_apigateway_arn_uses_documented_path_form():
    assert build_apigateway_arn('us-east-1', 'restapis/a1b2') == 'arn:aws:apigateway:us-east-1::/restapis/a1b2'
    assert build_apigateway_arn('us-east-1', 'restapis/a1b2/stages/prod') == \
        'arn:aws:apigateway:us-east-1::/restapis/a1b2/stages/prod'


def test_client_certificate_arns_have_no_account_and_leading_slash():
    certs = transform_client_certificates([{'clientCertificateId': 'c1'}], 'us-east-1', '123456789012')
    assert certs[0]['arn'] == 'arn:aws:apigateway:us-east-1::/clientcertificates/c1'

    stage_certs = transform_rest_api_client_certificate(
        [{'clientCertificateId': 'c2', 'createdDate': 'd'}], 'us-east-1', '123456789012',
    )
    assert stage_certs[0]['arn'] == 'arn:aws:apigateway:us-east-1::/clientcertificates/c2'


def test_console_link_still_deep_links_documented_arn():
    link = get_apigateway_console_link('arn:aws:apigateway:us-east-1::/restapis/a1b2')
    assert link.endswith('#/a1b2/resources/')


def test_parse_policy():
    res = parse_policy("1", test_data.DOUBLY_ESCAPED_POLICY)

    assert res == {'api_id': '1', 'internet_accessible': True}


def test_parse_policy_restricted_to_a_vpc_endpoint_is_not_internet_accessible():
    policy = (
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", '
        '"Action": "execute-api:Invoke", "Resource": "execute-api:/*", '
        '"Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]}'
    )

    assert parse_policy("1", policy) == {"api_id": "1", "internet_accessible": False}


def test_parse_policy_none_or_unparseable_is_unknown():
    # No policy, or one we cannot read, leaves the API's reachability to its endpoint type.
    assert parse_policy("1", None) == {"api_id": "1", "internet_accessible": None}
    assert parse_policy("2", "{not json") == {"api_id": "2", "internet_accessible": None}


def _domains_session(domains, mappings, domain_error=None, mapping_error=None):
    # domains: get_domain_names items; mappings: domain name -> get_base_path_mappings items.
    client = MagicMock()

    def paginator(operation):
        pages = MagicMock()
        if operation == 'get_domain_names':
            pages.paginate.side_effect = domain_error
            pages.paginate.return_value = [{'items': domains}]
        else:
            pages.paginate.side_effect = mapping_error or (lambda domainName: [{'items': mappings[domainName]}])
        return pages

    client.get_paginator.side_effect = paginator
    session = MagicMock()
    session.client.return_value = client
    return session


def _api(api_id, disabled, region='us-east-1'):
    return {'id': api_id, 'region': region, 'disableExecuteApiEndpoint': disabled}


def test_add_public_custom_domains_resolves_disabled_execute_api_endpoints():
    apis = [_api('api-public-domain', True), _api('api-private-domain', True), _api('api-no-domain', True)]
    session = _domains_session(
        [
            {'domainName': 'api.example.com', 'endpointConfiguration': {'types': ['REGIONAL']}},
            {'domainName': 'edge.example.com', 'endpointConfiguration': {'types': ['EDGE']}},
            {
                'domainName': 'internal.example.com', 'domainNameId': 'abc',
                'endpointConfiguration': {'types': ['PRIVATE']},
            },
        ],
        {
            'api.example.com': [{'basePath': 'v1', 'restApiId': 'api-public-domain'}],
            'edge.example.com': [{'basePath': '(none)', 'restApiId': 'api-public-domain'}],
        },
    )

    add_public_custom_domains(session, apis)

    assert {a['id']: a['public_custom_domains'] for a in apis} == {
        'api-public-domain': ['api.example.com', 'edge.example.com'],
        # Private custom domains are reachable only through VPC endpoints; their mappings are not read.
        'api-private-domain': [],
        'api-no-domain': [],
    }


def test_add_public_custom_domains_skips_regions_without_disabled_endpoints():
    apis = [_api('api-enabled', False), _api('api-default', None, 'eu-west-1')]
    session = _domains_session([], {})

    add_public_custom_domains(session, apis)

    session.client.assert_not_called()
    assert all('public_custom_domains' not in a for a in apis)


def test_add_public_custom_domains_unknown_when_unreadable():
    # Unknown (None) keeps the API public (fail-safe).
    denied = ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': 'no'}}, 'GetBasePathMappings')
    for kwargs in ({'domain_error': denied}, {'mapping_error': denied}):
        apis = [_api('api-disabled', True)]
        session = _domains_session(
            [{'domainName': 'api.example.com', 'endpointConfiguration': {'types': ['REGIONAL']}}],
            {'api.example.com': []}, **kwargs,
        )

        add_public_custom_domains(session, apis)

        assert apis[0]['public_custom_domains'] is None
