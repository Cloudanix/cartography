import datetime

DESCRIBE_FILE_SYSTEMS = [
    {
        'OwnerId': '123456789012',
        'CreationToken': 'console-1',
        'FileSystemId': 'fs-0123',
        'FileSystemArn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0123',
        'CreationTime': datetime.datetime(2026, 1, 2, 3, 4, 5, 678000, tzinfo=datetime.timezone.utc),
        'LifeCycleState': 'available',
        'Name': 'shared-home',
        'NumberOfMountTargets': 2,
        'SizeInBytes': {'Value': 6144},
        'PerformanceMode': 'generalPurpose',
        'Encrypted': True,
        'KmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/1111-2222',
        'ThroughputMode': 'bursting',
        'Tags': [],
    },
    {
        'OwnerId': '123456789012',
        'CreationToken': 'console-2',
        'FileSystemId': 'fs-0456',
        'FileSystemArn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-0456',
        'CreationTime': datetime.datetime(2026, 10, 1, 0, 0, 0, tzinfo=datetime.timezone.utc),
        'LifeCycleState': 'available',
        'NumberOfMountTargets': 0,
        'SizeInBytes': {'Value': 6144},
        'PerformanceMode': 'generalPurpose',
        'Encrypted': False,
        'ThroughputMode': 'elastic',
        'Tags': [],
    },
]
