import functools
import json

import cartography.intel.aws.mq
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import create_test_security_group_rule
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777772'
OTHER_ACCOUNT_ID = '888888888882'
ACTIVEMQ_ENDPOINTS = [{
    'ConsoleURL': 'https://b-x-1.mq.us-east-1.amazonaws.com:8162',
    'Endpoints': ['ssl://b-x-1.mq.us-east-1.amazonaws.com:61617'],
}]


def _load(neo4j_session, account_id, brokers):
    # Shape of get_mq_brokers() output; name -> (engine, PubliclyAccessible or 'unknown', security groups).
    raw = []
    for name, (engine, public, groups) in brokers.items():
        raw.append({
            'BrokerArn': f'arn:aws:mq:us-east-1:{account_id}:broker:{name}:b-{name}', 'BrokerId': f'b-{name}',
            'BrokerName': name, 'EngineType': engine, 'described': public != 'unknown',
            'PubliclyAccessible': public, 'SecurityGroups': groups,
            'BrokerInstances': ACTIVEMQ_ENDPOINTS if engine == 'ACTIVEMQ' else [],
        })
    cartography.intel.aws.mq.load_mq_brokers(
        neo4j_session, cartography.intel.aws.mq.transform_mq_brokers(raw, 'us-east-1'), account_id, TEST_UPDATE_TAG,
    )


def test_mq_broker_exposure(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-mqx', 'o-mqx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-mqx-other', 'o-mqx-other', OTHER_ACCOUNT_ID)
    _group = functools.partial(create_test_security_group_rule, neo4j_session)
    _group('mqx-sg-open-61617', '0.0.0.0/0', 'tcp', 61617, 61617)
    _group('mqx-sg-open-v6-console', '::/0', 'tcp', 8162, 8162)
    _group('mqx-sg-open-ssh', '0.0.0.0/0', 'tcp', 22, 22)
    _group('mqx-sg-vpc-only', '10.0.0.0/8', '-1', None, None)
    _group('mqx-sg-all-traffic', '0.0.0.0/0', '-1', -1, -1)
    _load(
        neo4j_session, ACCOUNT_ID, {
            'mqx-rabbit-public': ('RABBITMQ', True, []),
            'mqx-open': ('ACTIVEMQ', True, ['mqx-sg-open-61617']),
            'mqx-open-v6': ('ACTIVEMQ', True, ['mqx-sg-open-v6-console']),
            'mqx-all-traffic': ('ACTIVEMQ', True, ['mqx-sg-all-traffic']),
            'mqx-open-ssh-only': ('ACTIVEMQ', True, ['mqx-sg-open-ssh']),
            'mqx-vpc-only': ('ACTIVEMQ', True, ['mqx-sg-vpc-only']),
            'mqx-unsynced-group': ('ACTIVEMQ', True, ['mqx-sg-vpc-only', 'mqx-sg-never-synced']),
            'mqx-private': ('ACTIVEMQ', False, ['mqx-sg-open-61617']),
            'mqx-private-rabbit': ('RABBITMQ', False, []),
            'mqx-describe-failed': ('ACTIVEMQ', 'unknown', []),
            'mqx-stale': ('ACTIVEMQ', False, []),
        },
    )
    _load(neo4j_session, OTHER_ACCOUNT_ID, {'mqx-other-rabbit-public': ('RABBITMQ', True, [])})
    neo4j_session.run(
        "MATCH (b:AWSMQBroker{name: 'mqx-stale'}) "
        "SET b.exposed_internet = true, b.exposed_internet_type = ['direct_ipv4']",
    )

    run_analysis_job(
        'aws_mq_broker_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-mqx', 'o-mqx', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (b:AWSMQBroker) RETURN b.name AS name, b.exposed_internet AS exposed, "
        "b.exposed_internet_type AS types, b.publicContext AS context",
    )
    brokers = {r['name']: r for r in rows}
    assert {n: sorted(r['types']) for n, r in brokers.items() if r['exposed']} == {
        'mqx-rabbit-public': ['public_broker_no_security_group'],
        'mqx-open': ['direct_ipv4'],
        'mqx-open-v6': ['direct_ipv6'],
        'mqx-all-traffic': ['direct_ipv4'],
        'mqx-unsynced-group': ['public_broker_unresolved_security_group'],
        'mqx-describe-failed': ['public_access_unknown'],
    }
    context = json.loads(brokers['mqx-open']['context'])[0]
    assert context['resourceType'] == 'aws-applicationintegration-mq-broker'
    assert context['resource'] == f'arn:aws:mq:us-east-1:{ACCOUNT_ID}:broker:mqx-open:b-mqx-open'
    assert context['context'][0]['securityRules'] == [{
        'securityGroupId': 'mqx-sg-open-61617', 'fromPort': 61617, 'toPort': 61617, 'protocol': 'tcp',
        'ipRange': '0.0.0.0/0',
    }]
    assert brokers['mqx-stale']['context'] is None
