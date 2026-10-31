import json
from unittest.mock import MagicMock

from cartography.intel.aws import sns

OPEN = 'arn:aws:sns:us-east-1:111111111111:open'
SCOPED = 'arn:aws:sns:us-east-1:111111111111:scoped'
DEFAULT = 'arn:aws:sns:us-east-1:111111111111:default'


def _policy(condition=None):
    statement = {'Effect': 'Allow', 'Principal': {'AWS': '*'}, 'Action': 'SNS:Publish', 'Resource': '*'}
    if condition:
        statement['Condition'] = condition
    return json.dumps({'Statement': [statement]})


def test_transform_topics_evaluates_the_topic_policy(mocker):
    mocker.patch.object(sns, 'list_subscriptions', return_value=[])
    policies = {
        OPEN: _policy(),
        SCOPED: _policy({'StringEquals': {'AWS:SourceOwner': '111111111111'}}),
    }
    client = MagicMock()
    # Shape of get_topic_attributes(); a topic left at its default policy may have no Policy attribute here.
    client.get_topic_attributes.side_effect = lambda TopicArn: {
        'Attributes': {'TopicArn': TopicArn, **({'Policy': policies[TopicArn]} if TopicArn in policies else {})},
    }
    session = MagicMock()
    session.client.return_value = client

    topics = sns.transform_topics(session, [{'TopicArn': arn} for arn in (OPEN, SCOPED, DEFAULT)], 'us-east-1')

    assert {t['TopicArn']: t['policy_internet_accessible'] for t in topics} == {
        OPEN: True, SCOPED: False, DEFAULT: False,
    }
