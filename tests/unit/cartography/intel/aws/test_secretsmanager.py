"""Secrets Manager filters at the API via IncludePlannedDeletion=False."""
from unittest.mock import MagicMock

from cartography.intel.aws import secretsmanager


def test_get_secret_list_passes_include_planned_deletion_false():
    boto3_session = MagicMock()
    client = boto3_session.client.return_value
    paginator = client.get_paginator.return_value
    secret = {'ARN': 'arn:aws:secretsmanager:us-east-1:123456789012:secret:example'}
    paginator.paginate.return_value = [{'SecretList': [secret]}]

    result = secretsmanager.get_secret_list(boto3_session, 'us-east-1')

    client.get_paginator.assert_called_once_with('list_secrets')
    paginator.paginate.assert_called_once_with(IncludePlannedDeletion=False)
    assert result == [secret]
