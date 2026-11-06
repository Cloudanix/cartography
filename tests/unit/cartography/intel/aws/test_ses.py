from unittest.mock import MagicMock
from unittest.mock import patch

import boto3
import pytest

from cartography.intel.aws import ses

SESSION = boto3.Session(aws_access_key_id='fake', aws_secret_access_key='fake', region_name='us-east-1')


@pytest.mark.parametrize(
    'partition, regions, expected',
    [
        (None, ['us-east-1', 'eu-west-1'], ['us-east-1', 'eu-west-1']),
        ('aws-us-gov', ['us-gov-west-1', 'us-gov-east-1'], ['us-gov-west-1', 'us-gov-east-1']),
        # SES is not offered in the China partition.
        ('aws-cn', ['cn-north-1'], []),
    ],
)
def test_sync_queries_ses_regions_of_the_account_partition(partition, regions, expected):
    params = {} if partition is None else {'AWS_PARTITION': partition}
    with patch.object(ses, 'get_ses_identity', return_value=[]) as get_ids, \
            patch.object(ses, 'transform_identities', return_value=[]), \
            patch.object(ses, 'load_ses_identity'), patch.object(ses, 'cleanup_ses_identities'):
        ses.sync(MagicMock(), SESSION, regions, '123456789012', 1, params)
    assert [c.args[1] for c in get_ids.call_args_list] == expected
