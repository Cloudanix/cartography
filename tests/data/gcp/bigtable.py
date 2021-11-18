BIGTABLE_INSTANCE = [
    {
        'name': 'instance123',
        'displayName': 'bigtableinst123',
        'state': 'READY',
        'type': 'PRODUCTION',
        'createTime': '2021-10-02T15:01:23Z'
    },
    {
        'name': 'instance456',
        'displayName': 'bigtableinst456',
        'state': 'READY',
        'type': 'PRODUCTION',
        'createTime': '2021-10-02T15:01:23Z'
    },
]

BIGTABLE_CLUSTER = [
    {
        'name': 'cluster123',
        'location': 'us-east-1a',
        'state': 'READY',
        'serveNodes': 3,
        'defaultStorageType': 'SSD'
    },
    {
        'name': 'cluster456',
        'location': 'us-east-1a',
        'state': 'READY',
        'serveNodes': 3,
        'defaultStorageType': 'SSD'
    },
]

BIGTABLE_CLUSTER_BACKUP = [
    {
        'name': 'clusterbackup123',
        'sourceTable': 'table123',
        'expireTime': '2021-09-02T15:01:23Z',
        'startTime': '2022-09-02T00:00:00Z',
        'endTime': '2021-12-31T00:00:00Z',
        'sizeBytes': '256GB',
        'state': 'READY'
    },
    {
        'name': 'clusterbackup456',
        'sourceTable': 'table456',
        'expireTime': '2021-09-02T15:01:23Z',
        'startTime': '2022-09-02T00:00:00Z',
        'endTime': '2021-12-31T00:00:00Z',
        'sizeBytes': '256GB',
        'state': 'READY'
    }
]

BIGTABLE_TABLE = [
    {
        'name': 'table123',
        'replicationState': 'READY',
        'granularity': 'MILLIS',
        'sourceType': 'BACKUP'
    },
    {
        'name': 'table456',
        'replicationState': 'READY',
        'granularity': 'MILLIS',
        'sourceType': 'BACKUP'
    }
]
