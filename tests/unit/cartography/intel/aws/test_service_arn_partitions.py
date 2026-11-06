"""
Built (not API-returned) ARNs in the non-EC2 service modules follow the account's partition.
Each case: (region, partition kwarg, expected ARN prefix). A None kwarg exercises the 'aws' default.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from cartography.intel.aws import bedrock
from cartography.intel.aws import cloudwatch
from cartography.intel.aws import config
from cartography.intel.aws import dynamodb
from cartography.intel.aws import elasticsearch
from cartography.intel.aws import lambda_function
from cartography.intel.aws import rds
from cartography.intel.aws import redshift
from cartography.intel.aws import s3
from cartography.intel.aws import ses
from cartography.intel.aws import ssm

ACCOUNT = '123456789012'
CASES = [
    ('us-east-1', None, 'arn:aws:'),
    ('us-gov-west-1', 'aws-us-gov', 'arn:aws-us-gov:'),
    ('cn-north-1', 'aws-cn', 'arn:aws-cn:'),
]


def _kw(partition):
    return {} if partition is None else {'partition': partition}


def _console_arns(module):
    """Patch the module's console linker so each call returns (and records) the ARN it was given."""
    linker = MagicMock()
    linker.get_console_link.side_effect = lambda *args, **kwargs: kwargs.get('arn', args[0] if args else None)
    return patch.object(module, 'aws_console_link', linker), linker


def _linked_arns(linker):
    return [c.kwargs.get('arn', c.args[0] if c.args else None) for c in linker.get_console_link.call_args_list]


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_redshift_arns(region, partition, prefix):
    nodes = redshift.transform_reserved_nodes([{'ReservedNodeId': 'rn-1'}], region, ACCOUNT, **_kw(partition))
    assert nodes[0]['arn'] == f'{prefix}redshift:{region}:{ACCOUNT}:reserved-node/rn-1'

    clusters = [{'region': region, 'ClusterIdentifier': 'c1'}]
    redshift.transform_redshift_cluster_data(clusters, ACCOUNT, **_kw(partition))
    assert clusters[0]['arn'] == f'{prefix}redshift:{region}:{ACCOUNT}:cluster:c1'

    clusters[0]['VpcSecurityGroups'] = [{'GroupId': 'sg-1', 'VpcSecurityGroupId': 'sg-1', 'region': region}]
    patcher, linker = _console_arns(redshift)
    with patcher, patch.object(redshift, 'load_graph_data'):
        redshift._attach_ec2_security_groups(MagicMock(), clusters, 1, ACCOUNT, **_kw(partition))
    assert _linked_arns(linker) == [f'{prefix}ec2:{region}:{ACCOUNT}:security-group/sg-1']


def test_redshift_sync_threads_partition_from_common_job_parameters():
    with patch.object(redshift, 'get_redshift_reserved_node', return_value=[{'ReservedNodeId': 'rn-1'}]), \
            patch.object(redshift, 'load_redshift_reserved_node') as load, \
            patch.object(redshift, 'cleanup_redshift_reserved_node'):
        redshift.sync_redshift_reserved_node(
            MagicMock(), MagicMock(), ['cn-north-1'], ACCOUNT, 1, {'AWS_PARTITION': 'aws-cn'},
        )
    assert load.call_args.args[1][0]['arn'] == f'arn:aws-cn:redshift:cn-north-1:{ACCOUNT}:reserved-node/rn-1'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_rds_arns(region, partition, prefix):
    patcher, linker = _console_arns(rds)
    with patcher:
        rds.transform_rds_sgs([{'DBSecurityGroupName': 'dbsg'}], region, ACCOUNT, **_kw(partition))
    assert _linked_arns(linker) == [f'{prefix}ec2:{region}:{ACCOUNT}:security-group/dbsg']

    instance = {
        'region': region, 'DBInstanceArn': 'from-api',
        'DBSubnetGroup': {'DBSubnetGroupName': 'sng', 'Subnets': [{'SubnetIdentifier': 'subnet-1'}]},
    }
    with patch.object(rds, 'load_graph_data') as load:
        rds._attach_ec2_subnet_groups(MagicMock(), [instance], ACCOUNT, 1, **_kw(partition))
    expected = f'{prefix}rds:{region}:{ACCOUNT}:subgrp:sng'
    assert load.call_args_list[0].args[2][0]['arn'] == expected
    assert load.call_args_list[1].args[2][0]['sng_arn'] == expected


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_elasticsearch_arns(region, partition, prefix):
    domains = elasticsearch.transform_es_domains([{'DomainName': 'd1'}], region, ACCOUNT, **_kw(partition))
    assert domains[0]['arn'] == f'{prefix}es:{region}:{ACCOUNT}:domain/d1'

    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {'ReservedElasticsearchInstances': [{'ReservedElasticsearchInstanceId': 'ri-1', 'State': 'active'}]},
    ]
    reserved = elasticsearch.get_elasticsearch_reserved_instances(client, region, ACCOUNT, **_kw(partition))
    assert reserved[0]['arn'] == f'{prefix}es:{region}:{ACCOUNT}:reserved-instances/ri-1'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_dynamodb_gsi_console_arn(region, partition, prefix):
    throughput = {'ReadCapacityUnits': 1, 'WriteCapacityUnits': 1}
    gsi = {'IndexArn': 'from-api/i', 'IndexName': 'i', 'ProvisionedThroughput': throughput}
    table = {
        'Table': {
            'TableArn': 'from-api', 'TableName': 't1', 'ItemCount': 0, 'TableSizeBytes': 0,
            'ProvisionedThroughput': throughput,
            'GlobalSecondaryIndexes': [gsi],
        },
    }
    patcher, linker = _console_arns(dynamodb)
    with patcher:
        dynamodb.transform_dynamodb_tables([table], region, ACCOUNT, **_kw(partition))
    assert _linked_arns(linker) == ['from-api', f'{prefix}dynamodb:{region}:{ACCOUNT}:secondary_indexes/t1']


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_s3_bucket_arn(region, partition, prefix):
    data = {'Buckets': [{'Name': 'b1', 'Region': region, 'CreationDate': 'd'}]}
    with patch.object(s3, 'run_write_query') as write:
        s3.load_s3_buckets(MagicMock(), data, ACCOUNT, 1, **_kw(partition))
    assert write.call_args.kwargs['Arn'] == f'{prefix}s3:::b1'
    assert write.call_args.kwargs['BucketName'] == 'b1'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_bedrock_agent_arn(region, partition, prefix):
    session = MagicMock()
    session.client.return_value.get_paginator.return_value.paginate.return_value = [
        {'agentSummaries': [{'agentId': 'a1'}]},
    ]
    agents = bedrock.get_bedrock_agents_list(session, ACCOUNT, region, **_kw(partition))
    assert agents[0]['arn'] == f'{prefix}bedrock:{region}:{ACCOUNT}:agent/a1'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_lambda_detail_console_arns(region, partition, prefix):
    function_arn = f'{prefix}lambda:{region}:{ACCOUNT}:function:fn'
    details = [(function_arn, [{}], [{}], [{}], region)]
    patcher, linker = _console_arns(lambda_function)
    with patcher, patch.object(lambda_function, '_load_lambda_function_aliases'), \
            patch.object(lambda_function, '_load_lambda_event_source_mappings'), \
            patch.object(lambda_function, '_load_lambda_layers'):
        lambda_function.load_lambda_function_details(MagicMock(), details, 1, ACCOUNT, **_kw(partition))
    assert _linked_arns(linker) == [
        f'{prefix}lambda:{region}:{ACCOUNT}:alias/fn',
        f'{prefix}lambda:{region}:{ACCOUNT}:event-source-mapping/fn',
        f'{prefix}lambda:{region}:{ACCOUNT}:layer/fn',
    ]


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_ssm_console_arns(region, partition, prefix):
    patcher, linker = _console_arns(ssm)
    with patcher:
        ssm.transform_instance_information([{'InstanceId': 'i-1'}], region, ACCOUNT, **_kw(partition))
        ssm.transform_instance_patches([{'_instance_id': 'i-1', 'Title': 't'}], region, ACCOUNT, **_kw(partition))
    assert _linked_arns(linker) == [f'{prefix}ssm:{region}:{ACCOUNT}:managed-instance/i-1'] * 2


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_ses_identity_arn(region, partition, prefix):
    identities = ses.transform_identities(MagicMock(), ['example.com'], region, ACCOUNT, **_kw(partition))
    assert identities[0]['arn'] == f'{prefix}ses:{region}:{ACCOUNT}:identity/example.com'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_config_console_arns(region, partition, prefix):
    patcher, linker = _console_arns(config)
    with patcher, patch.object(config, 'load_graph_data'):
        config.load_configuration_recorders(MagicMock(), [{'name': 'default'}], region, ACCOUNT, 1, **_kw(partition))
        config.load_delivery_channels(MagicMock(), [{'name': 'default'}], region, ACCOUNT, 1, **_kw(partition))
    assert _linked_arns(linker) == [
        f'{prefix}config:{region}:{ACCOUNT}:configuration-recorder/default',
        f'{prefix}config:{region}:{ACCOUNT}:delivery-channel/default',
    ]


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_cloudwatch_arns(region, partition, prefix):
    flowlogs = cloudwatch.transform_flow_logs([{'FlowLogId': 'fl-1'}], ACCOUNT, region, **_kw(partition))
    # 'vcp-flow-log' is the existing (misspelt) id format; only the partition is in scope here.
    assert flowlogs[0]['arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:vcp-flow-log/fl-1'

    metrics = cloudwatch.transform_metrics([{'MetricName': 'm1'}], ACCOUNT, region, **_kw(partition))
    assert metrics[0]['arn'] == f'{prefix}cloudwatch:{region}:{ACCOUNT}:metrics/m1'
    # EventBridge rule links use the rule's own Arn from the API, so no partition is built for them.
