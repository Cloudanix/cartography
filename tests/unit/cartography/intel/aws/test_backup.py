from datetime import datetime
from datetime import timedelta
from datetime import timezone
from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.aws import backup
from tests.data.aws.backup import LIST_BACKUP_JOBS
from tests.data.aws.backup import LIST_PROTECTED_RESOURCES


def _session_with_pages(pages):
    session = MagicMock()
    session.client.return_value.get_paginator.return_value.paginate.return_value = pages
    return session


def test_get_backup_jobs_only_asks_for_recent_jobs_in_large_pages():
    session = _session_with_pages([{'BackupJobs': LIST_BACKUP_JOBS}])

    jobs = backup.get_backup_jobs(session, 'us-east-1')

    assert jobs == LIST_BACKUP_JOBS
    paginator = session.client.return_value.get_paginator
    paginator.assert_called_once_with('list_backup_jobs')
    kwargs = paginator.return_value.paginate.call_args.kwargs
    expected_after = datetime.now(timezone.utc) - timedelta(days=backup.BACKUP_JOB_LOOKBACK_DAYS)
    assert abs(kwargs['ByCreatedAfter'] - expected_after) < timedelta(minutes=1)
    assert kwargs['PaginationConfig'] == {'PageSize': 1000}


def test_get_backup_jobs_stops_at_the_region_cap_and_warns(caplog):
    requested_pages = []

    def pages():
        for number in range(3):
            requested_pages.append(number)
            yield {'BackupJobs': [{'BackupJobId': f'job-{number}-{i}'} for i in range(4)]}

    session = _session_with_pages(pages())

    with patch.object(backup, 'MAX_BACKUP_JOBS_PER_REGION', 6):
        jobs = backup.get_backup_jobs(session, 'us-east-1')

    assert len(jobs) == 6
    assert requested_pages == [0, 1]
    assert "ingesting the first 6 only" in caplog.text


def test_transform_backup_jobs():
    transformed = backup.transform_backup_jobs(LIST_BACKUP_JOBS + [{'State': 'COMPLETED'}])

    assert transformed == [
        {
            'BackupJobId': 'job-completed-1',
            'ResourceArn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123',
            'ResourceType': 'EFS',
            'RecoveryPointArn': 'arn:aws:backup:us-east-1:123456789012:recovery-point:rp-1',
            'RecoveryPointDeleteAfterDays': 35,
            # Whole seconds, 'T' separator: the evaluator parses '%Y-%m-%dT%H:%M:%S%z'.
            'CreationDate': '2026-10-30T05:00:00+00:00',
            'CompletionDate': '2026-10-30T05:20:00+00:00',
            'State': 'COMPLETED',
            'BackupVaultName': 'Default',
            'BackupVaultArn': 'arn:aws:backup:us-east-1:123456789012:backup-vault:Default',
        },
        {
            'BackupJobId': 'job-running-2',
            'ResourceArn': 'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0abc',
            'ResourceType': 'FSx',
            'RecoveryPointArn': None,
            'RecoveryPointDeleteAfterDays': None,
            'CreationDate': '2026-10-31T05:00:00+00:00',
            'CompletionDate': None,
            'State': 'RUNNING',
            'BackupVaultName': 'Default',
            'BackupVaultArn': 'arn:aws:backup:us-east-1:123456789012:backup-vault:Default',
        },
    ]
    assert datetime.strptime(transformed[0]['CreationDate'], '%Y-%m-%dT%H:%M:%S%z')


def test_transform_protected_resources():
    transformed = backup.transform_protected_resources(LIST_PROTECTED_RESOURCES + [{'ResourceType': 'EFS'}])

    assert transformed == [
        {
            'ResourceArn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123',
            'ResourceType': 'EFS',
            'ResourceName': 'shared-home',
            'LastBackupTime': '2026-10-30T05:20:00+00:00',
            'LastRecoveryPointArn': 'arn:aws:backup:us-east-1:123456789012:recovery-point:rp-1',
        },
    ]


def test_sync_reads_every_region():
    with patch.object(backup, 'get_backup_jobs', return_value=[]) as get_jobs, \
            patch.object(backup, 'get_protected_resources', return_value=[]) as get_protected, \
            patch.object(backup, 'load_backup_jobs'), patch.object(backup, 'load_protected_resources'), \
            patch.object(backup, 'cleanup_backup') as cleanup:
        backup.sync(MagicMock(), MagicMock(), ['us-east-1', 'eu-west-1'], '123456789012', 1, {})

    assert [c.args[1] for c in get_jobs.call_args_list] == ['us-east-1', 'eu-west-1']
    assert [c.args[1] for c in get_protected.call_args_list] == ['us-east-1', 'eu-west-1']
    cleanup.assert_called_once()
