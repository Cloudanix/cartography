import datetime

DESCRIBE_FILE_SYSTEMS = [
    {
        'OwnerId': '123456789012',
        'CreationTime': datetime.datetime(2026, 2, 3, 4, 5, 6, tzinfo=datetime.timezone.utc),
        'FileSystemId': 'fs-0abc',
        'FileSystemType': 'WINDOWS',
        'Lifecycle': 'AVAILABLE',
        'StorageCapacity': 300,
        'StorageType': 'SSD',
        'VpcId': 'vpc-0fsx',
        'SubnetIds': ['subnet-0a', 'subnet-0b'],
        'NetworkInterfaceIds': ['eni-0a'],
        'DNSName': 'amznfsxabc.corp.example.com',
        'KmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/3333-4444',
        'ResourceARN': 'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0abc',
        'Tags': [],
        'WindowsConfiguration': {'ThroughputCapacity': 32, 'AutomaticBackupRetentionDays': 7},
    },
    {
        'OwnerId': '123456789012',
        'CreationTime': datetime.datetime(2026, 9, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
        'FileSystemId': 'fs-0def',
        'FileSystemType': 'LUSTRE',
        'Lifecycle': 'AVAILABLE',
        'StorageCapacity': 1200,
        'StorageType': 'SSD',
        'VpcId': 'vpc-0fsx',
        'SubnetIds': ['subnet-0a'],
        'DNSName': 'fs-0def.fsx.us-east-1.amazonaws.com',
        'ResourceARN': 'arn:aws:fsx:us-east-1:123456789012:file-system/fs-0def',
        'Tags': [],
        # Scratch Lustre has no automatic backups.
        'LustreConfiguration': {'DeploymentType': 'SCRATCH_2', 'AutomaticBackupRetentionDays': 0},
    },
]
