import json

import cartography.intel.aws.sns
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777774'
OTHER_ACCOUNT_ID = '888888888884'


def _topic_arn(account_id, name):
    return f'arn:aws:sns:us-east-1:{account_id}:{name}'


def _load(neo4j_session, account_id, topics):
    # Shape of transform_topics() output.
    cartography.intel.aws.sns.load_sns_topic(
        neo4j_session, [
            {
                'TopicArn': _topic_arn(account_id, name), 'name': name, 'region': 'us-east-1',
                'attributes': {}, 'policy_internet_accessible': accessible,
            }
            for name, accessible in topics
        ], account_id, TEST_UPDATE_TAG,
    )


def test_sns_topic_public_when_policy_is_internet_accessible(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-snsx', 'o-snsx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-snsx-other', 'o-snsx-other', OTHER_ACCOUNT_ID)
    _load(
        neo4j_session, ACCOUNT_ID, [
            ('snsx-open', True), ('snsx-scoped', False), ('snsx-unparseable', None), ('snsx-closed-since', False),
        ],
    )
    _load(neo4j_session, OTHER_ACCOUNT_ID, [('snsx-other-open', True)])
    neo4j_session.run(
        "MATCH (t:AWSSNSTopic{name: 'snsx-closed-since'}) "
        "SET t.exposed_internet = true, t.exposed_internet_type = ['resource_policy']",
    )

    run_analysis_job(
        'aws_sns_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-snsx', 'o-snsx', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (t:AWSSNSTopic) RETURN t.name AS name, t.exposed_internet AS exposed, "
        "t.exposed_internet_type AS types, t.publicContext AS context",
    )
    topics = {r['name']: r for r in rows}
    assert {n for n, r in topics.items() if r['exposed']} == {'snsx-open'}
    assert topics['snsx-open']['types'] == ['resource_policy']
    context = json.loads(topics['snsx-open']['context'])[0]
    assert (context['resourceType'], context['context'][0]['topicArn']) == (
        'aws-applicationintegration-sns-topic', _topic_arn(ACCOUNT_ID, 'snsx-open'),
    )
    assert topics['snsx-closed-since']['context'] is None
