from unittest import mock
from unittest.mock import MagicMock

import cartography.intel.aws.iam
from cartography.intel.aws.iam import sync_user_managed_policies
from tests.data.aws.iam.user_policies import GET_USER_LIST_DATA
from tests.data.aws.iam.user_policies import GET_USER_MANAGED_POLS_SAMPLE

AWS_UPDATE_TAG = 111111
AWS_ACCOUNT_ID = "1234"


@mock.patch.object(cartography.intel.aws.iam, 'get_user_managed_policy_data', return_value=GET_USER_MANAGED_POLS_SAMPLE)
def test_sync_user_managed_policies(mock_get_user_pols: MagicMock):
    # Arrange
    boto3_session = mock.MagicMock()
    neo4j_session = mock.MagicMock()

    # Act
    sync_user_managed_policies(boto3_session, GET_USER_LIST_DATA, neo4j_session, AWS_ACCOUNT_ID, AWS_UPDATE_TAG)

    # Assert: policies land as UNWIND batches (arn-matched + sso id-matched) plus one
    # statements batch = 3 writes total, with the expected policy ids in the rows.
    assert neo4j_session.execute_write.call_count == 3
    policy_call = neo4j_session.execute_write.call_args_list[0]
    policy_ids = {row["policy_id"] for row in policy_call.kwargs["DictList"]}
    assert policy_ids == {
        '1234/managed_policy/arn:aws:iam::1234:policy/user1-user-policy',
        '1234/managed_policy/arn:aws:iam::aws:policy/AmazonS3FullAccess',
        '1234/managed_policy/arn:aws:iam::aws:policy/AWSLambda_FullAccess',
        '1234/managed_policy/arn:aws:iam::aws:policy/AdministratorAccess',
    }
    principal_arns = {row["principal_arn"] for row in policy_call.kwargs["DictList"]}
    assert principal_arns == {'arn:aws:iam::1234:user/user1', 'arn:aws:iam::1234:user/user3'}
