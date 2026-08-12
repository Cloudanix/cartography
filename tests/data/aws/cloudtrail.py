DESCRIBE_CLOUDTRAIL_TRAILS = [
    {
        "Name": "test-trail",
        "HomeRegion": "us-east-1",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail",
        "IsMultiRegionTrail": True,
        "IsOrganizationTrail": False,
        "LogFileValidationEnabled": True,
        "S3BucketName": "test-bucket",
        "S3KeyPrefix": "test-prefix",
        "IncludeGlobalServiceEvents": True,
        "HasCustomEventSelectors": False,
        "HasInsightSelectors": False,
        "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/test-key",
        "CloudWatchLogsLogGroupArn": "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/lambda/process-orders:*",
        "EventSelectors": [
            {
                "ReadWriteType": "All",
                "IncludeManagementEvents": True,
                "DataResources": [
                    {
                        "Type": "AWS::S3::Object",
                        "Values": ["arn:aws:s3:::example-bucket/"],
                    }
                ],
            }
        ],
        "AdvancedEventSelectors": [],
    }
]

BUCKETS = {
    "Buckets": [
        {
            "Name": "test-bucket",
            "Region": "us-east-1",
            "CreationDate": "2021-01-01",
        }
    ]
}


DESCRIBE_TRAILS = [
    {
        'Name': 'trail1',
        'S3BucketName': 'bucket-1',
        'S3KeyPrefix': 's3_key_prefix_1',
        'SnsTopicName': 'topic1',
        'SnsTopicARN': 'snstopic-arn',
        'IncludeGlobalServiceEvents': True,
        'IsMultiRegionTrail': True,
        'HomeRegion': 'us-central1',
        'TrailARN': 'trail1_arn',
        'LogFileValidationEnabled': True,
        'CloudWatchLogsLogGroupArn': 'cloud_watch_logs_log_group_arn',
        'CloudWatchLogsRoleArn': 'cloud_watch_logs_role_arn',
        'KmsKeyId': 'kmskey',
        'HasCustomEventSelectors': True,
        'HasInsightSelectors': True,
        'IsOrganizationTrail': True,
    },
    {
        'Name': 'trail2',
        'S3BucketName': 'bucket-2',
        'S3KeyPrefix': 's3_key_prefix_2',
        'SnsTopicName': 'topic2',
        'SnsTopicARN': 'snstopic-arn',
        'IncludeGlobalServiceEvents': True,
        'IsMultiRegionTrail': True,
        'HomeRegion': 'us-central2',
        'TrailARN': 'trail2_arn',
        'LogFileValidationEnabled': True,
        'CloudWatchLogsLogGroupArn': 'cloud_watch_logs_log_group_arn',
        'CloudWatchLogsRoleArn': 'cloud_watch_logs_role_arn',
        'KmsKeyId': 'kmskey',
        'HasCustomEventSelectors': True,
        'HasInsightSelectors': True,
        'IsOrganizationTrail': True,
    },
]

