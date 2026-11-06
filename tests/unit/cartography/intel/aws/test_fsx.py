from unittest.mock import MagicMock

from cartography.intel.aws import fsx
from tests.data.aws.fsx import DESCRIBE_FILE_SYSTEMS


def test_get_fsx_file_systems_uses_only_the_list_call():
    session = MagicMock()
    client = session.client.return_value
    client.get_paginator.return_value.paginate.return_value = [{'FileSystems': DESCRIBE_FILE_SYSTEMS}]

    assert fsx.get_fsx_file_systems(session, 'us-east-1') == DESCRIBE_FILE_SYSTEMS
    client.get_paginator.assert_called_once_with('describe_file_systems')


def test_transform_fsx_file_systems():
    transformed = fsx.transform_fsx_file_systems(DESCRIBE_FILE_SYSTEMS + [{'FileSystemId': 'fs-no-arn'}])

    assert len(transformed) == 2
    windows, lustre = transformed
    assert windows['ResourceARN'] == 'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0abc'
    assert windows['CreationTime'] == '2026-02-03T04:05:06+00:00'
    assert windows['VpcId'] == 'vpc-0fsx'
    assert windows['SubnetIds'] == ['subnet-0a', 'subnet-0b']
    assert windows['consolelink'] == (
        'https://us-east-1.console.aws.amazon.com/fsx/home?region=us-east-1#file-systems/fs-0abc'
    )
    # Native backups come from whichever per-type block the file system has.
    assert windows['AutomaticBackupRetentionDays'] == 7
    assert lustre['AutomaticBackupRetentionDays'] == 0
    assert lustre['KmsKeyId'] is None


def test_automatic_backup_retention_days_is_none_without_a_type_block():
    assert fsx._automatic_backup_retention_days({'FileSystemType': 'ONTAP'}) is None
    assert fsx._automatic_backup_retention_days({'OntapConfiguration': None}) is None
    assert fsx._automatic_backup_retention_days({'OpenZFSConfiguration': {'AutomaticBackupRetentionDays': 3}}) == 3
