from datetime import datetime
from unittest.mock import MagicMock

from cartography.intel.aws import efs
from tests.data.aws.efs import DESCRIBE_FILE_SYSTEMS


def test_get_efs_file_systems_uses_one_list_call_per_page_and_nothing_per_file_system():
    session = MagicMock()
    client = session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [{'FileSystems': DESCRIBE_FILE_SYSTEMS}]

    assert efs.get_efs_file_systems(session, 'us-east-1') == DESCRIBE_FILE_SYSTEMS
    client.get_paginator.assert_called_once_with('describe_file_systems')
    assert client.describe_mount_targets.call_count == 0
    assert client.describe_backup_policy.call_count == 0


def test_transform_efs_file_systems():
    transformed = efs.transform_efs_file_systems(DESCRIBE_FILE_SYSTEMS + [{'FileSystemId': 'fs-no-arn'}])

    assert [fs['FileSystemArn'] for fs in transformed] == [
        'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123',
        'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0456',
    ]
    first = transformed[0]
    assert first['FileSystemId'] == 'fs-0123'
    assert first['Name'] == 'shared-home'
    assert first['Encrypted'] is True
    assert first['KmsKeyId'] == 'arn:aws:kms:us-east-1:123456789012:key/1111-2222'
    # Same ISO-8601 shape as the backup job dates the evaluator compares against.
    assert first['CreationTime'] == '2026-01-02T03:04:05+00:00'
    assert datetime.strptime(first['CreationTime'], '%Y-%m-%dT%H:%M:%S%z')
    assert first['consolelink'] == (
        'https://us-east-1.console.aws.amazon.com/efs/home?region=us-east-1#/file-systems/fs-0123'
    )
    assert transformed[1]['Encrypted'] is False
    assert transformed[1]['KmsKeyId'] is None
