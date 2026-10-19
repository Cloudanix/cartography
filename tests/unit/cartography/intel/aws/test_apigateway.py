import tests.data.aws.apigateway as test_data
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

    assert (res) is not None
    assert (res['api_id']) is not None
    assert (res['internet_accessible']) is not None
    assert (res['accessible_actions']) is not None


def test_none_policy():
    res = parse_policy(None, None)

    assert (res) is None
