from unittest.mock import MagicMock

from botocore.exceptions import EndpointConnectionError

import cartography.intel.aws
from cartography.intel.aws import dms

INSTANCE_ARN = 'arn:aws:dms:us-east-1:111111111111:rep:ABC'
ENDPOINT_ARN = 'arn:aws:dms:us-east-1:111111111111:endpoint:XYZ'


def _session(pages=None, error=None):
    paginator = MagicMock()
    if error:
        paginator.paginate.side_effect = error
    else:
        paginator.paginate.return_value = pages
    client = MagicMock()
    client.get_paginator.return_value = paginator
    session = MagicMock()
    session.client.return_value = client
    return session, client


def test_get_replication_instances_reads_every_page():
    session, client = _session(pages=[{'ReplicationInstances': [{'a': 1}]}, {'ReplicationInstances': [{'b': 2}]}])

    assert dms.get_replication_instances(session, 'us-east-1') == [{'a': 1}, {'b': 2}]
    client.get_paginator.assert_called_once_with('describe_replication_instances')


def test_get_endpoints_skips_a_region_without_dms():
    session, _ = _session(error=EndpointConnectionError(endpoint_url='https://dms.xx-1.amazonaws.com'))

    assert dms.get_endpoints(session, 'xx-1') == []


def test_transform_replication_instances_keeps_network_ids_and_public_ips():
    instances = [
        {
            'ReplicationInstanceArn': INSTANCE_ARN, 'ReplicationInstanceIdentifier': 'rep-1',
            'PubliclyAccessible': True, 'AutoMinorVersionUpgrade': False,
            'ReplicationInstancePublicIpAddress': '54.1.1.1',
            'ReplicationInstancePublicIpAddresses': ['54.1.1.1', None],
            'ReplicationInstancePrivateIpAddresses': ['10.0.0.5'],
            'VpcSecurityGroups': [{'VpcSecurityGroupId': 'sg-1', 'Status': 'active'}, {'Status': 'active'}],
            'ReplicationSubnetGroup': {
                'ReplicationSubnetGroupIdentifier': 'default-vpc-1', 'VpcId': 'vpc-1',
                'Subnets': [{'SubnetIdentifier': 'subnet-a'}, {'SubnetIdentifier': 'subnet-b'}],
            },
        },
        # Still creating: only the deprecated singular IP field, no subnet group yet.
        {'ReplicationInstanceArn': INSTANCE_ARN + '2', 'ReplicationInstancePublicIpAddress': '54.2.2.2'},
        {'ReplicationInstanceIdentifier': 'no-arn'},
    ]

    rows = dms.transform_replication_instances(instances, 'us-east-1')

    assert len(rows) == 2
    first = rows[0]
    assert (first['identifier'], first['publiclyAccessible'], first['autoMinorVersionUpgrade']) == (
        'rep-1', True, False,
    )
    assert (first['publicIpAddresses'], first['privateIpAddresses']) == (['54.1.1.1'], ['10.0.0.5'])
    assert (first['securityGroupIds'], first['vpcId'], first['subnetIds']) == (
        ['sg-1'], 'vpc-1', ['subnet-a', 'subnet-b'],
    )
    assert first['consolelink'].startswith('https://')
    assert (rows[1]['publicIpAddresses'], rows[1]['securityGroupIds'], rows[1]['subnetIds']) == (['54.2.2.2'], [], [])


def test_transform_endpoints_reads_a_missing_ssl_mode_as_none():
    endpoints = [
        {
            'EndpointArn': ENDPOINT_ARN, 'EndpointIdentifier': 'src', 'EndpointType': 'SOURCE',
            'EngineName': 'postgres', 'ServerName': 'db.example.com', 'Port': 5432, 'SslMode': 'verify-full',
        },
        {'EndpointArn': ENDPOINT_ARN + '2', 'EndpointIdentifier': 'tgt', 'EndpointType': 'TARGET', 'EngineName': 's3'},
    ]

    rows = dms.transform_endpoints(endpoints, 'us-east-1')

    assert [(r['identifier'], r['sslMode']) for r in rows] == [('src', 'verify-full'), ('tgt', 'none')]
    assert (rows[0]['port'], rows[0]['region']) == (5432, 'us-east-1')


def _sync_account(mocker, monkeypatch, requested, link_side_effect=None):
    """Run _sync_one_account sequentially with stub services; return the call order."""
    monkeypatch.setenv('LOCAL_RUN', '1')
    order = []
    mocker.patch.dict(
        cartography.intel.aws.RESOURCE_FUNCTIONS,
        {'dms': lambda **_: order.append('dms'), 'ec2:security_group': lambda **_: order.append('sg')},
    )
    mocker.patch.object(cartography.intel.aws, '_resolve_sync_regions', return_value=['us-east-1'])
    mocker.patch.object(cartography.intel.aws, '_build_aws_sync_kwargs', return_value={})
    mocker.patch.object(cartography.intel.aws, 'run_cleanup_job')
    mocker.patch.object(cartography.intel.aws, 'run_analysis_job', side_effect=lambda *_: order.append('analysis'))
    mocker.patch.object(
        cartography.intel.aws, 'link_replication_instance_networks',
        side_effect=link_side_effect or (lambda *_: order.append('link')),
    )
    config = MagicMock()
    config.aws_excluded_regions = None
    config.refresh_entitlements = False

    cartography.intel.aws._sync_one_account(
        MagicMock(), MagicMock(), '111111111111', 42, {'AWS_ID': '111111111111'}, ['us-east-1'], requested,
        creds={}, config=config,
    )
    return order


def test_account_sync_links_dms_networks_after_the_syncs_and_before_analysis(mocker, monkeypatch):
    order = _sync_account(mocker, monkeypatch, ['dms', 'ec2:security_group'])

    assert order.index('link') > max(order.index('dms'), order.index('sg'))
    assert order.index('link') < order.index('analysis')


def test_account_sync_skips_dms_links_when_dms_not_requested(mocker, monkeypatch):
    assert 'link' not in _sync_account(mocker, monkeypatch, ['ec2:security_group'])


def test_account_sync_continues_when_dms_links_fail(mocker, monkeypatch):
    def _boom(*_):
        raise RuntimeError('neo4j down')

    assert 'analysis' in _sync_account(mocker, monkeypatch, ['dms'], link_side_effect=_boom)
