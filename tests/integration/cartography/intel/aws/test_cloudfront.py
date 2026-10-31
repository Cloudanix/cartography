import cartography.intel.aws.cloudfront
from cartography.intel.aws.cloudfront import load_cloudfront_distributions
from cartography.util import run_analysis_job
from tests.data.aws.cloudfront import DESCRIBE_DISTRIBUTION_RESPONSE
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters


TEST_UPDATE_TAG = 123456789


def test_load_cloudfront_distributions_data(neo4j_session):
    _ensure_local_neo4j_has_test_cloudfront_distributions_data(neo4j_session)
    expected_nodes = {
        "arn:aws:cloudfront::123456789012:distribution/EDFDVBD632BHDS5",
    }
    nodes = neo4j_session.run(
        """
        MATCH (n:AWSCloudfrontDistribution) RETURN n.id;
        """,
    )
    actual_nodes = {n['n.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def _distribution(dist_id, enabled, viewer_protocol_policy):
    return {
        'ARN': f'arn:aws:cloudfront::111111111111:distribution/{dist_id}',
        'Id': dist_id,
        'Enabled': enabled,
        'DefaultCacheBehavior': {'ViewerProtocolPolicy': viewer_protocol_policy},
        's3BucketNames': [],
    }


def _exposed_distributions(neo4j_session, account_id):
    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(d:AWSCloudfrontDistribution{exposed_internet: true})
        RETURN d.name AS name, d.exposed_internet_type AS types, d.publicContext AS context
        """,
        account_id=account_id,
    )
    return {n['name']: (n['types'], n['context'] is not None) for n in nodes}


def test_cloudfront_exposure_marks_enabled_distributions_public(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-cf', 'o-cf', '111111111111')
    create_test_org_account(neo4j_session, 'ws-cf-other', 'o-cf-other', '222222222222')
    load_cloudfront_distributions(
        neo4j_session, [
            _distribution('cf-https', True, 'redirect-to-https'),
            _distribution('cf-allow-all', True, 'allow-all'),
            _distribution('cf-disabled', False, 'allow-all'),
        ], '111111111111', TEST_UPDATE_TAG,
    )
    load_cloudfront_distributions(
        neo4j_session, [_distribution('cf-other-ws', True, 'https-only')], '222222222222', TEST_UPDATE_TAG,
    )
    # Left over from an earlier sync: the clean-up must clear it now that the distribution is disabled.
    neo4j_session.run(
        "MATCH (d:AWSCloudfrontDistribution{name: 'cf-disabled'}) SET d.exposed_internet = true",
    )

    run_analysis_job(
        'aws_cloudfront_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-cf', 'o-cf', '111111111111', TEST_UPDATE_TAG + 1),
    )

    assert _exposed_distributions(neo4j_session, '111111111111') == {
        'cf-https': (['enabled_distribution'], True),
        'cf-allow-all': (['enabled_distribution'], True),
    }
    # Another workspace's distribution is not touched by this account's job.
    assert _exposed_distributions(neo4j_session, '222222222222') == {}


def _ensure_local_neo4j_has_test_cloudfront_distributions_data(neo4j_session):
    cartography.intel.aws.cloudfront.load_cloudfront_distributions(
        neo4j_session,
        DESCRIBE_DISTRIBUTION_RESPONSE,
        '123456789012',
        TEST_UPDATE_TAG,
    )
