from unittest.mock import MagicMock

from botocore.exceptions import ClientError
from botocore.exceptions import EndpointConnectionError

from cartography.intel.aws import s3

ACCOUNT_ID = '123456789012'
ACCOUNT_BLOCK = {
    'PublicAccessBlockConfiguration': {
        'BlockPublicAcls': True, 'IgnorePublicAcls': True,
        'BlockPublicPolicy': False, 'RestrictPublicBuckets': True,
    },
}


def _session(response=None, error=None):
    session = MagicMock()
    get_block = session.client.return_value.get_public_access_block
    get_block.return_value = response
    get_block.side_effect = error
    return session


def _client_error(code):
    return ClientError({'Error': {'Code': code, 'Message': code}}, 'GetPublicAccessBlock')


def test_account_public_access_block_set():
    session = _session(response=ACCOUNT_BLOCK)

    block = s3.get_account_public_access_block(session, ACCOUNT_ID, 'eu-west-1')

    assert s3.parse_account_public_access_block(block) == {
        's3_block_public_acls': True,
        's3_ignore_public_acls': True,
        's3_block_public_policy': False,
        's3_restrict_public_buckets': True,
    }
    session.client.assert_called_once()
    assert session.client.call_args.args == ('s3control',)
    assert session.client.call_args.kwargs['region_name'] == 'eu-west-1'
    session.client.return_value.get_public_access_block.assert_called_once_with(AccountId=ACCOUNT_ID)


def test_account_public_access_block_not_configured_blocks_nothing():
    block = s3.get_account_public_access_block(
        _session(error=_client_error('NoSuchPublicAccessBlockConfiguration')), ACCOUNT_ID, 'us-east-1',
    )

    assert s3.parse_account_public_access_block(block) == {
        's3_block_public_acls': False,
        's3_ignore_public_acls': False,
        's3_block_public_policy': False,
        's3_restrict_public_buckets': False,
    }


def test_account_public_access_block_unknown_when_unreadable():
    # Unknown is stored as null, which the exposure gate reads as "not blocked" (fail-safe).
    unknown = dict.fromkeys(
        ['s3_block_public_acls', 's3_ignore_public_acls', 's3_block_public_policy', 's3_restrict_public_buckets'],
    )
    for error in (_client_error('AccessDenied'), EndpointConnectionError(endpoint_url='https://s3-control')):
        block = s3.get_account_public_access_block(_session(error=error), ACCOUNT_ID, 'us-east-1')

        assert block is None
        assert s3.parse_account_public_access_block(block) == unknown
