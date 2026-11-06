import json

import cartography.intel.aws.sqs
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
REGION = 'us-east-1'
ACCOUNT_ID = '777777777775'
OTHER_ACCOUNT_ID = '888888888885'


def _queue_arn(account_id, name):
    return f'arn:aws:sqs:{REGION}:{account_id}:{name}'


def _policy(account_id, name, principal, condition=None):
    statement = {
        'Effect': 'Allow', 'Principal': principal, 'Action': 'sqs:SendMessage',
        'Resource': _queue_arn(account_id, name),
    }
    if condition:
        statement['Condition'] = condition
    return json.dumps({'Version': '2012-10-17', 'Statement': [statement]})


def _load(neo4j_session, account_id, queues):
    # Shape of get_sqs_queue_attributes(): queue URL -> get_queue_attributes()['Attributes'].
    data = {}
    for name, policy in queues:
        attributes = {
            'QueueArn': _queue_arn(account_id, name), 'CreatedTimestamp': '1627539901900',
            'LastModifiedTimestamp': '1627539901900',
        }
        if policy:
            attributes['Policy'] = policy
        data[f'https://sqs.{REGION}.amazonaws.com/{account_id}/{name}'] = attributes
    cartography.intel.aws.sqs.load_sqs_queues(neo4j_session, data, REGION, account_id, TEST_UPDATE_TAG)


def test_sqs_queue_public_when_policy_is_internet_accessible(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-sqsx', 'o-sqsx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-sqsx-other', 'o-sqsx-other', OTHER_ACCOUNT_ID)
    _load(
        neo4j_session, ACCOUNT_ID, [
            ('sqsx-open', _policy(ACCOUNT_ID, 'sqsx-open', '*')),
            (
                'sqsx-from-topic', _policy(
                    ACCOUNT_ID, 'sqsx-from-topic', {'Service': 'sns.amazonaws.com'},
                    {'ArnEquals': {'aws:SourceArn': f'arn:aws:sns:{REGION}:{ACCOUNT_ID}:alerts'}},
                ),
            ),
            (
                'sqsx-any-principal-own-account', _policy(
                    ACCOUNT_ID, 'sqsx-any-principal-own-account', {'AWS': '*'},
                    {'StringEquals': {'aws:SourceAccount': ACCOUNT_ID}},
                ),
            ),
            ('sqsx-no-policy', None),
            ('sqsx-closed-since', None),
        ],
    )
    _load(neo4j_session, OTHER_ACCOUNT_ID, [('sqsx-other-open', _policy(OTHER_ACCOUNT_ID, 'sqsx-other-open', '*'))])
    neo4j_session.run(
        "MATCH (q:SQSQueue{name: 'sqsx-closed-since'}) "
        "SET q.exposed_internet = true, q.exposed_internet_type = ['resource_policy']",
    )

    run_analysis_job(
        'aws_sqs_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-sqsx', 'o-sqsx', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (q:SQSQueue) WHERE q.name STARTS WITH 'sqsx' RETURN q.name AS name, q.exposed_internet AS exposed, "
        "q.exposed_internet_type AS types, q.publicContext AS context",
    )
    queues = {r['name']: r for r in rows}
    assert {n for n, r in queues.items() if r['exposed']} == {'sqsx-open'}
    assert queues['sqsx-open']['types'] == ['resource_policy']
    context = json.loads(queues['sqsx-open']['context'])[0]
    assert (context['resourceType'], context['context'][0]['queueArn']) == (
        'aws-applicationintegration-sqs-queue', _queue_arn(ACCOUNT_ID, 'sqsx-open'),
    )
    assert queues['sqsx-closed-since']['context'] is None
