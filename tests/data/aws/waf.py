DESCRIBE_WAF_ACLS_RESPONSE = [
    {
        'name': 'my-web-acl',
        'Scope': 'REGIONAL',
        'Id': '12345678-1234-1234-1234-123456789012',
        'arn': 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-web-acl/12345678-1234-1234-1234-123456789012',
        'DefaultAction': {'Allow': {}},
        'Description': 'My test WAF ACL',
        'Rules': [],
        'VisibilityConfig': {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': 'myWebAclMetric',
        },
        'CreatedAt': '2021-01-01T00:00:00Z',
        'LastUpdated': '2021-01-02T00:00:00Z',
        'region': 'us-east-1',
        'consolelink': 'https://console.aws.amazon.com/wafv2/home?region=us-east-1#/webacls/12345678-1234-1234-1234-123456789012',
    },
]

DESCRIBE_WAF_CLASSIC_ACLS_RESPONSE = [
    {
        'name': 'my-classic-web-acl',
        'Id': '12345678-1234-1234-1234-123456789012',
        'arn': 'arn:aws:waf::123456789012:regional/webacl/my-classic-web-acl/12345678-1234-1234-1234-123456789012',
        'DefaultAction': {'Type': 'ALLOW'},
        'Description': 'My test Classic WAF ACL',
        'Rules': [],
        'CreatedAt': '2021-01-01T00:00:00Z',
        'LastUpdated': '2021-01-02T00:00:00Z',
        'region': 'us-east-1',
        'consolelink': 'https://console.aws.amazon.com/wafv2/home?region=us-east-1#/webacls/12345678-1234-1234-1234-123456789012',

    },
]
