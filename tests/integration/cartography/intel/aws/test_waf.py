import cartography.intel.aws.waf
from tests.data.aws.waf import DESCRIBE_WAF_ACLS_RESPONSE
from tests.data.aws.waf import DESCRIBE_WAF_CLASSIC_ACLS_RESPONSE

TEST_UPDATE_TAG = 123456789


def test_load_wafv2_acls_data(neo4j_session):
    _ensure_local_neo4j_has_test_wafv2_acls_data(neo4j_session)
    expected_nodes = {
        "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-web-acl/12345678-1234-1234-1234-123456789012",
    }
    nodes = neo4j_session.run(
        """
        MATCH (n:AWSWAFv2WebACL) RETURN n.id;
        """,
    )
    actual_nodes = {n['n.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def _ensure_local_neo4j_has_test_wafv2_acls_data(neo4j_session):
    cartography.intel.aws.waf.load_waf_v2_web_acls(
        neo4j_session,
        DESCRIBE_WAF_ACLS_RESPONSE,
        '123456789012',
        TEST_UPDATE_TAG,
    )


def test_load_waf_classic_acls_data(neo4j_session):
    _ensure_local_neo4j_has_test_waf_classic_acls_data(neo4j_session)
    expected_nodes = {
        "arn:aws:waf::123456789012:regional/webacl/my-classic-web-acl/12345678-1234-1234-1234-123456789012",
    }
    nodes = neo4j_session.run(
        """
        MATCH (n:AWSWAFClassicWebACL) RETURN n.id;
        """,
    )
    actual_nodes = {n['n.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def _ensure_local_neo4j_has_test_waf_classic_acls_data(neo4j_session):
    cartography.intel.aws.waf.load_waf_classic_web_acls(
        neo4j_session,
        DESCRIBE_WAF_CLASSIC_ACLS_RESPONSE,
        '123456789012',
        TEST_UPDATE_TAG,
    )
