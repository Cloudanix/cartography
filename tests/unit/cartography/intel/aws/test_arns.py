from types import SimpleNamespace

import boto3
import pytest

from cartography.intel.aws import _get_account_partition
from cartography.intel.aws.util.arns import build_arn
from cartography.intel.aws.util.arns import get_partition
from cartography.intel.aws.util.arns import get_partition_from_params
from cartography.intel.aws.util.arns import PARTITION_PARAM

SESSION = boto3.Session(aws_access_key_id='fake', aws_secret_access_key='fake', region_name='us-east-1')


@pytest.mark.parametrize(
    'region, expected',
    [
        ('us-east-1', 'aws'),
        ('eu-west-1', 'aws'),
        ('us-gov-west-1', 'aws-us-gov'),
        ('cn-north-1', 'aws-cn'),
        (None, 'aws'),
        ('', 'aws'),
        ('not-a-region-1', 'aws'),
    ],
)
def test_get_partition(region, expected):
    assert get_partition(SESSION, region) == expected


def test_get_partition_from_params_defaults_to_aws():
    assert get_partition_from_params({}) == 'aws'
    assert get_partition_from_params({PARTITION_PARAM: 'aws-cn'}) == 'aws-cn'


@pytest.mark.parametrize(
    'params, expected',
    [
        ({'defaultRegion': 'us-gov-west-1', 'regions': ['us-east-1']}, 'aws-us-gov'),
        ({'regions': ['cn-north-1', 'cn-northwest-1']}, 'aws-cn'),
        ({'regions': []}, 'aws'),  # falls back to the session region (us-east-1)
    ],
)
def test_get_account_partition(params, expected):
    assert _get_account_partition(SESSION, SimpleNamespace(params=params)) == expected


def test_build_arn_partition():
    assert build_arn('ec2', '123', 'volume', 'vol-1', 'us-east-1') == 'arn:aws:ec2:us-east-1:123:volume/vol-1'
    assert build_arn('ec2', '123', 'volume', 'vol-1', 'cn-north-1', 'aws-cn') == \
        'arn:aws-cn:ec2:cn-north-1:123:volume/vol-1'
