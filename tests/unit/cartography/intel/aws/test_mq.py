from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cartography.intel.aws import mq

ARN = 'arn:aws:mq:us-east-1:111111111111:broker:'


def _summary(name, engine):
    return {
        'BrokerArn': f'{ARN}{name}:b-{name}', 'BrokerId': f'b-{name}', 'BrokerName': name,
        'BrokerState': 'RUNNING', 'EngineType': engine, 'DeploymentMode': 'SINGLE_INSTANCE',
    }


def _client(summaries, described):
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{'BrokerSummaries': summaries}]

    def describe(BrokerId):
        if BrokerId not in described:
            raise ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': 'denied'}}, 'DescribeBroker')
        return described[BrokerId]

    client.describe_broker.side_effect = describe
    return client


def test_get_mq_brokers_reads_public_flag_groups_and_endpoints_from_describe():
    # list_brokers carries no PubliclyAccessible, security groups or endpoints; describe_broker does.
    described = {
        'b-active': {
            **_summary('active', 'ACTIVEMQ'),
            'PubliclyAccessible': True, 'SecurityGroups': ['sg-1'], 'SubnetIds': ['subnet-1'],
            'BrokerInstances': [{
                'ConsoleURL': 'https://b-active-1.mq.us-east-1.amazonaws.com:8162',
                'Endpoints': [
                    'ssl://b-active-1.mq.us-east-1.amazonaws.com:61617',
                    'amqp+ssl://b-active-1.mq.us-east-1.amazonaws.com:5671',
                ],
                'IpAddress': '3.3.3.3',
            }],
            'Logs': {'Audit': True, 'General': False},
            'EncryptionOptions': {'UseAwsOwnedKey': True},
        },
        'b-rabbit': {
            **_summary('rabbit', 'RABBITMQ'), 'PubliclyAccessible': True, 'SubnetIds': ['subnet-2'],
            'BrokerInstances': [{
                'ConsoleURL': 'https://b-rabbit.mq.us-east-1.amazonaws.com',
                'Endpoints': ['amqps://b-rabbit.mq.us-east-1.amazonaws.com:5671'],
            }],
        },
    }
    session = MagicMock()
    session.client.return_value = _client(
        [_summary('active', 'ACTIVEMQ'), _summary('rabbit', 'RABBITMQ'), _summary('denied', 'ACTIVEMQ')], described,
    )

    raw = mq.get_mq_brokers(session, 'us-east-1')
    brokers = {b['BrokerName']: b for b in mq.transform_mq_brokers(raw, 'us-east-1')}

    active = brokers['active']
    assert active['PubliclyAccessible'] is True
    assert active['SecurityGroups'] == ['sg-1']
    assert active['SubnetIds'] == ['subnet-1']
    assert active['Ports'] == [5671, 8162, 61617]
    assert active['IpAddresses'] == ['3.3.3.3']
    assert (active['AuditLog'], active['GeneralLog'], active['UseAwsOwnedKey']) == (True, False, True)
    assert active['consolelink'].startswith('https://')
    # RabbitMQ: no security groups; the console URL has no port, so HTTPS 443.
    assert brokers['rabbit']['SecurityGroups'] == []
    assert brokers['rabbit']['Ports'] == [443, 5671]
    # describe_broker denied: the broker is kept from its summary, its public flag is unknown (None), not False.
    denied = brokers['denied']
    assert denied['PubliclyAccessible'] is None
    assert denied['EngineType'] == 'ACTIVEMQ'
    assert denied['SecurityGroups'] == [] and denied['Ports'] == []


def test_load_mq_brokers_is_batched_and_links_groups_and_subnets():
    session = MagicMock()
    brokers = mq.transform_mq_brokers(
        [{
            **_summary('active', 'ACTIVEMQ'), 'described': True, 'PubliclyAccessible': False,
            'SecurityGroups': ['sg-1', 'sg-2'], 'SubnetIds': ['subnet-1'],
        }],
        'us-east-1',
    )

    mq.load_mq_brokers(session, brokers, '111111111111', 42)

    session.run.assert_not_called()
    queries = [c.args[1] for c in session.execute_write.call_args_list]
    assert all('UNWIND $DictList' in q for q in queries)
    rows = [c.kwargs['DictList'] for c in session.execute_write.call_args_list]
    assert rows[1] == [
        {'arn': f'{ARN}active:b-active', 'group_id': 'sg-1'}, {'arn': f'{ARN}active:b-active', 'group_id': 'sg-2'},
    ]
    assert rows[2] == [{'arn': f'{ARN}active:b-active', 'subnet_id': 'subnet-1'}]


def test_sync_skips_regions_without_amazon_mq(mocker):
    session = MagicMock()
    session.get_available_regions.return_value = ['us-east-1']
    get = mocker.patch.object(mq, 'get_mq_brokers', return_value=[])
    mocker.patch.object(mq, 'load_mq_brokers')
    mocker.patch.object(mq, 'cleanup')

    mq.sync(MagicMock(), session, ['us-east-1', 'xx-new-1'], '111111111111', 42, {'AWS_ID': '111111111111'})

    assert [c.args[1] for c in get.call_args_list] == ['us-east-1']
