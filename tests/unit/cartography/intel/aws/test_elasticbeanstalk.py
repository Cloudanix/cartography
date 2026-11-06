from unittest.mock import MagicMock

from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError

import cartography.intel.aws
from cartography.intel.aws import elasticbeanstalk

ENV_ARN = 'arn:aws:elasticbeanstalk:us-east-1:111111111111:environment/shop/shop-prod'
ALB_ARN = 'arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/awseb-AWSEB-1/abc'


def _client(pages, resources=None, resources_error=None):
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = pages
    if resources_error:
        client.describe_environment_resources.side_effect = resources_error
    else:
        client.describe_environment_resources.side_effect = lambda EnvironmentId: {
            'EnvironmentResources': resources[EnvironmentId],
        }
    client.describe_configuration_settings.return_value = {
        'ConfigurationSettings': [{
            'OptionSettings': [
                {'Namespace': 'aws:elbv2:listener:443', 'OptionName': 'Protocol', 'Value': 'HTTPS'},
                {'Namespace': 'aws:elbv2:listener:default', 'OptionName': 'Protocol', 'Value': 'HTTP'},
                {'Namespace': 'aws:elbv2:listener:8443', 'OptionName': 'Protocol', 'Value': 'HTTPS'},
                {
                    'Namespace': 'aws:elasticbeanstalk:environment', 'OptionName': 'EnvironmentType',
                    'Value': 'LoadBalanced',
                },
            ],
        }],
    }
    session = MagicMock()
    session.client.return_value = client
    return session, client


def _env(env_id, status='Ready'):
    return {
        'EnvironmentId': env_id, 'EnvironmentName': env_id, 'ApplicationName': 'shop', 'Status': status,
        'EnvironmentArn': ENV_ARN + env_id,
    }


def test_get_environments_skips_terminated_and_attaches_resources_and_settings():
    session, client = _client(
        pages=[{'Environments': [_env('e-1')]}, {'Environments': [_env('e-2', 'Terminated')]}],
        resources={'e-1': {'LoadBalancers': [{'Name': ALB_ARN}], 'Instances': [{'Id': 'i-1'}]}},
    )

    environments = elasticbeanstalk.get_environments(session, 'us-east-1')

    assert [e['EnvironmentId'] for e in environments] == ['e-1']
    assert environments[0]['EnvironmentResources']['LoadBalancers'] == [{'Name': ALB_ARN}]
    client.get_paginator.return_value.paginate.assert_called_once_with(IncludeDeleted=False)
    client.describe_environment_resources.assert_called_once_with(EnvironmentId='e-1')


def test_get_environments_marks_resources_unknown_when_the_describe_fails():
    error = ClientError({'Error': {'Code': 'InvalidParameterValue', 'Message': 'boom'}}, 'DescribeEnvironmentResources')
    session, _ = _client(pages=[{'Environments': [_env('e-1')]}], resources_error=error)

    environments = elasticbeanstalk.get_environments(session, 'us-east-1')

    assert environments[0]['EnvironmentResources'] is None


def test_get_environments_skips_a_region_without_beanstalk():
    session, client = _client(pages=[])
    client.get_paginator.return_value.paginate.side_effect = EndpointConnectionError(endpoint_url='https://eb.xx-1')

    assert elasticbeanstalk.get_environments(session, 'xx-1') == []


def test_transform_environments_keeps_tier_resources_and_listener_protocols():
    session, _ = _client(
        pages=[{
            'Environments': [
                {**_env('e-1'), 'Tier': {'Name': 'WebServer', 'Type': 'Standard'}, 'CNAME': 'shop.eb.com'},
                _env('e-2'),
            ],
        }],
        resources={
            'e-1': {'LoadBalancers': [{'Name': ALB_ARN}, {}], 'Instances': [{'Id': 'i-1'}, {'Id': 'i-2'}]},
            'e-2': {},
        },
    )
    environments = elasticbeanstalk.get_environments(session, 'us-east-1')
    environments[1]['EnvironmentResources'] = None
    environments.append({'EnvironmentName': 'no-arn'})

    rows = elasticbeanstalk.transform_environments(environments, 'us-east-1')

    assert [r['environmentId'] for r in rows] == ['e-1', 'e-2']
    first = rows[0]
    assert (first['tierName'], first['tierType'], first['cname']) == (
        'WebServer', 'Standard', 'shop.eb.com',
    )
    assert (first['loadBalancerNames'], first['instanceIds'], first['resourcesResolved']) == (
        [ALB_ARN], ['i-1', 'i-2'], True,
    )
    assert (first['listenerProtocols'], first['environmentType']) == (['HTTPS', 'HTTP'], 'LoadBalanced')
    assert (rows[1]['resourcesResolved'], rows[1]['loadBalancerNames'], rows[1]['instanceIds']) == (False, [], [])


def _sync_account(mocker, monkeypatch, requested, link_side_effect=None):
    """Run _sync_one_account sequentially with stub services; return the call order."""
    monkeypatch.setenv('LOCAL_RUN', '1')
    order = []
    mocker.patch.dict(
        cartography.intel.aws.RESOURCE_FUNCTIONS,
        {
            'elasticbeanstalk': lambda **_: order.append('elasticbeanstalk'),
            'ec2:load_balancer_v2': lambda **_: order.append('elbv2'),
            'ec2:instance': lambda **_: order.append('ec2'),
        },
    )
    mocker.patch.object(cartography.intel.aws, '_resolve_sync_regions', return_value=['us-east-1'])
    mocker.patch.object(cartography.intel.aws, '_build_aws_sync_kwargs', return_value={})
    mocker.patch.object(cartography.intel.aws, 'run_cleanup_job')
    mocker.patch.object(cartography.intel.aws, 'run_analysis_job', side_effect=lambda *_: order.append('analysis'))
    mocker.patch.object(cartography.intel.aws, 'sync_eks_node_links')
    mocker.patch.object(
        cartography.intel.aws, 'link_environment_resources',
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


def test_account_sync_links_beanstalk_resources_after_the_syncs_and_before_analysis(mocker, monkeypatch):
    order = _sync_account(mocker, monkeypatch, ['elasticbeanstalk', 'ec2:load_balancer_v2', 'ec2:instance'])

    assert order.index('link') > max(order.index('elasticbeanstalk'), order.index('elbv2'), order.index('ec2'))
    assert order.index('link') < order.index('analysis')


def test_account_sync_skips_beanstalk_links_when_not_requested(mocker, monkeypatch):
    assert 'link' not in _sync_account(mocker, monkeypatch, ['ec2:instance'])


def test_account_sync_continues_when_beanstalk_links_fail(mocker, monkeypatch):
    def _boom(*_):
        raise RuntimeError('neo4j down')

    assert 'analysis' in _sync_account(mocker, monkeypatch, ['elasticbeanstalk'], link_side_effect=_boom)
