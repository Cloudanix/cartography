import datetime

LIST_BACKUP_JOBS = [
    {
        'BackupJobId': 'job-completed-1',
        'BackupVaultName': 'Default',
        'BackupVaultArn': 'arn:aws:backup:us-east-1:123456789012:backup-vault:Default',
        'RecoveryPointArn': 'arn:aws:backup:us-east-1:123456789012:recovery-point:rp-1',
        'RecoveryPointLifecycle': {'DeleteAfterDays': 35},
        'ResourceArn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123',
        'ResourceType': 'EFS',
        'CreationDate': datetime.datetime(2026, 10, 30, 5, 0, 0, 123000, tzinfo=datetime.timezone.utc),
        'CompletionDate': datetime.datetime(2026, 10, 30, 5, 20, 0, tzinfo=datetime.timezone.utc),
        'State': 'COMPLETED',
    },
    {
        # A running job has no recovery point and no lifecycle yet.
        'BackupJobId': 'job-running-2',
        'BackupVaultName': 'Default',
        'BackupVaultArn': 'arn:aws:backup:us-east-1:123456789012:backup-vault:Default',
        'ResourceArn': 'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0abc',
        'ResourceType': 'FSx',
        'CreationDate': datetime.datetime(2026, 10, 31, 5, 0, 0, tzinfo=datetime.timezone.utc),
        'State': 'RUNNING',
    },
]

LIST_PROTECTED_RESOURCES = [
    {
        'ResourceArn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123',
        'ResourceType': 'EFS',
        'ResourceName': 'shared-home',
        'LastBackupTime': datetime.datetime(2026, 10, 30, 5, 20, 0, tzinfo=datetime.timezone.utc),
        'LastRecoveryPointArn': 'arn:aws:backup:us-east-1:123456789012:recovery-point:rp-1',
    },
]
