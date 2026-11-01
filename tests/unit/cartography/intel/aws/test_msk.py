from unittest.mock import MagicMock

from cartography.intel.aws import msk

ARN = 'arn:aws:kafka:us-east-1:111111111111:cluster/'

PROVISIONED = {
    'ClusterArn': ARN + 'prov/uuid-1', 'ClusterName': 'prov', 'ClusterType': 'PROVISIONED', 'State': 'ACTIVE',
    'Provisioned': {
        'BrokerNodeGroupInfo': {
            'InstanceType': 'kafka.m5.large', 'ClientSubnets': ['subnet-1', 'subnet-2'], 'SecurityGroups': ['sg-1'],
            'ConnectivityInfo': {'PublicAccess': {'Type': 'SERVICE_PROVIDED_EIPS'}},
        },
        'CurrentBrokerSoftwareInfo': {'KafkaVersion': '3.6.0'},
        'ClientAuthentication': {'Sasl': {'Iam': {'Enabled': True}, 'Scram': {'Enabled': False}}},
        'EncryptionInfo': {
            'EncryptionAtRest': {'DataVolumeKMSKeyId': 'key-1'},
            'EncryptionInTransit': {'ClientBroker': 'TLS', 'InCluster': True},
        },
        'NumberOfBrokerNodes': 2,
    },
}
SERVERLESS = {
    'ClusterArn': ARN + 'srv/uuid-2', 'ClusterName': 'srv', 'ClusterType': 'SERVERLESS', 'State': 'ACTIVE',
    'Serverless': {
        'VpcConfigs': [{'SubnetIds': ['subnet-3'], 'SecurityGroupIds': ['sg-3']}],
        'ClientAuthentication': {'Sasl': {'Iam': {'Enabled': True}}},
    },
}


def test_get_and_transform_msk_clusters_reads_network_and_security_from_the_list_call():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [{'ClusterInfoList': [PROVISIONED, SERVERLESS]}]
    session = MagicMock()
    session.client.return_value = client

    clusters = {
        c['ClusterName']: c
        for c in msk.transform_msk_clusters(msk.get_msk_clusters(session, 'us-east-1'), 'us-east-1')
    }

    client.get_paginator.assert_called_once_with('list_clusters_v2')
    prov = clusters['prov']
    assert (prov['PublicAccessType'], prov['SecurityGroups'], prov['SubnetIds']) == (
        'SERVICE_PROVIDED_EIPS', ['sg-1'], ['subnet-1', 'subnet-2'],
    )
    assert (prov['IamAuth'], prov['ScramAuth'], prov['TlsAuth'], prov['UnauthenticatedAccess']) == (
        True, False, False, False,
    )
    assert (prov['KafkaVersion'], prov['ClientBrokerEncryption'], prov['InClusterEncryption'], prov['KmsKeyId']) == (
        '3.6.0', 'TLS', True, 'key-1',
    )
    assert prov['consolelink'].startswith('https://')
    # Serverless: no public access setting; groups and subnets come from the VPC configs.
    srv = clusters['srv']
    assert (srv['PublicAccessType'], srv['SecurityGroups'], srv['SubnetIds'], srv['IamAuth']) == (
        None, ['sg-3'], ['subnet-3'], True,
    )


def test_load_msk_clusters_is_batched_and_links_groups_and_subnets():
    session = MagicMock()

    msk.load_msk_clusters(session, msk.transform_msk_clusters([PROVISIONED], 'us-east-1'), '111111111111', 42)

    session.run.assert_not_called()
    calls = session.execute_write.call_args_list
    assert all('UNWIND $DictList' in c.args[1] for c in calls)
    assert calls[1].kwargs['DictList'] == [{'arn': ARN + 'prov/uuid-1', 'group_id': 'sg-1'}]
    assert [r['subnet_id'] for r in calls[2].kwargs['DictList']] == ['subnet-1', 'subnet-2']


def test_sync_skips_regions_without_msk(mocker):
    session = MagicMock()
    session.get_available_regions.return_value = ['us-east-1']
    get = mocker.patch.object(msk, 'get_msk_clusters', return_value=[])
    mocker.patch.object(msk, 'load_msk_clusters')
    mocker.patch.object(msk, 'cleanup')

    msk.sync(MagicMock(), session, ['us-east-1', 'xx-new-1'], '111111111111', 42, {'AWS_ID': '111111111111'})

    session.get_available_regions.assert_called_once_with('kafka', partition_name='aws')
    assert [c.args[1] for c in get.call_args_list] == ['us-east-1']
