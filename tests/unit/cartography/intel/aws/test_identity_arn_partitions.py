"""
Built ARNs in apigateway, iam, organizations and route53 follow the account's partition.
Each case: (region, partition kwarg, expected ARN prefix). A None kwarg exercises the 'aws' default.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from cartography.intel.aws import apigateway
from cartography.intel.aws import iam
from cartography.intel.aws import organizations
from cartography.intel.aws import route53

ACCOUNT = '123456789012'
CASES = [
    ('us-east-1', None, 'arn:aws:'),
    ('us-gov-west-1', 'aws-us-gov', 'arn:aws-us-gov:'),
    ('cn-north-1', 'aws-cn', 'arn:aws-cn:'),
]


def _kw(partition):
    return {} if partition is None else {'partition': partition}


def _params(partition):
    return {} if partition is None else {'AWS_PARTITION': partition}


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_apigateway_arns(region, partition, prefix):
    assert apigateway.build_apigateway_arn(region, 'restapis/a1', **_kw(partition)) == \
        f'{prefix}apigateway:{region}::/restapis/a1'

    certs = apigateway.transform_client_certificates([{'clientCertificateId': 'c1'}], region, ACCOUNT, **_kw(partition))
    assert certs[0]['arn'] == f'{prefix}apigateway:{region}::/clientcertificates/c1'

    stages = [{'region': region, 'apiId': 'a1', 'stageName': 'prod', 'createdDate': 'd'}]
    with patch.object(apigateway, 'load_graph_data'):
        apigateway._load_apigateway_stages(MagicMock(), stages, 1, **_kw(partition))
    assert stages[0]['arn'] == f'{prefix}apigateway:{region}::/restapis/a1/stages/prod'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_apigateway_sync_threads_partition(region, partition, prefix):
    with patch.object(apigateway, 'get_client_certificates', return_value=[{'clientCertificateId': 'c1'}]), \
            patch.object(apigateway, 'load_client_certificates') as load, \
            patch.object(apigateway, 'cleanup_client_certificates'):
        apigateway.sync_client_certificates(MagicMock(), MagicMock(), [region], ACCOUNT, 1, _params(partition))
    loaded = load.call_args.args[1]
    assert loaded[0]['arn'] == f'{prefix}apigateway:{region}::/clientcertificates/c1'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_iam_inline_policy_arn(region, partition, prefix):
    policy_map = {f'{prefix}iam::{ACCOUNT}:user/u1': {'p1': []}}
    with patch.object(iam, '_batch_load_policies') as load, patch.object(iam, '_batch_load_policy_statements'):
        iam.load_policy_data(MagicMock(), policy_map, 'inline', ACCOUNT, 1, **_kw(partition))
    assert load.call_args.args[1][0]['policy_arn'] == f'{prefix}iam::{ACCOUNT}:policy/p1'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_iam_access_key_user_arn(region, partition, prefix):
    session = MagicMock()
    session.execute_read.return_value = [{'name': 'u1'}]
    with patch.object(iam, 'get_account_access_key_data', return_value=[{'AccessKeyId': 'k'}]), \
            patch.object(iam, 'load_user_access_keys') as load, patch.object(iam, 'run_cleanup_job'):
        iam.sync_user_access_keys(session, MagicMock(), ACCOUNT, 1, _params(partition))
    assert list(load.call_args.args[1]) == [f'{prefix}iam::{ACCOUNT}:user/u1']


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_organizations_root_arn(region, partition, prefix):
    params = {'WORKSPACE_ID': 'w', 'WORKSPACE_NAME': 'w', **_params(partition)}
    with patch.object(organizations, 'run_write_query') as write, patch.object(organizations, 'cleanup'):
        organizations.load_aws_accounts(MagicMock(), {'default': ACCOUNT}, 1, {'Id': 'o-1'}, params)
    assert write.call_args.kwargs['RootArn'] == f'{prefix}iam::{ACCOUNT}:root'


@pytest.mark.parametrize('region, partition, prefix', CASES)
def test_route53_arns(region, partition, prefix):
    zone = {
        'Id': '/hostedzone/Z1', 'Name': 'example.com.', 'Config': {'PrivateZone': False},
        'ResourceRecordSetCount': 1,
    }
    record_set = {'Name': 'www.example.com.', 'Type': 'A', 'ResourceRecords': [{'Value': '1.2.3.4'}]}
    with patch.object(route53, 'get_zone_record_sets', return_value=[record_set]):
        zones = route53.transform_zones(MagicMock(), [zone], **_kw(partition))
    # The API Id carries "/hostedzone/"; the ARN must hold only the bare zone id.
    assert zones[0][0]['arn'] == f'{prefix}route53:::hostedzone/Z1'

    with patch.object(route53, 'load_zone'), patch.object(route53, 'load_a_records') as load_a, \
            patch.object(route53, 'link_aws_resources'):
        route53.load_dns_details(MagicMock(), zones, ACCOUNT, 1, **_kw(partition))
    assert load_a.call_args.args[1][0]['arn'] == f'{prefix}route53:::recordset//hostedzone/Z1/www.example.com/A'
