MOCK_INSTANCES = {
    "instances": [
        {
            "name": "projects/test-project/instances/carto-bt-instance",
            "displayName": "carto-bt-instance",
            "state": "READY",
            "type": "PRODUCTION",
            "labels": {
                "env": "dev",
                "team": "data",
            },
        },
    ],
}

MOCK_CLUSTERS = {
    "clusters": [
        {
            "name": "projects/test-project/instances/carto-bt-instance/clusters/carto-bt-cluster-c1",
            "location": "projects/test-project/locations/us-central1-b",
            "state": "READY",
            "defaultStorageType": "SSD",
        },
    ],
}

MOCK_TABLES = {
    "tables": [
        {
            "name": "projects/test-project/instances/carto-bt-instance/tables/carto-test-table",
            "granularity": "MILLIS",
        },
    ],
}

MOCK_APP_PROFILES = {
    "appProfiles": [
        {
            "name": "projects/test-project/instances/carto-bt-instance/appProfiles/carto-app-profile",
            "description": "Test profile",
            "singleClusterRouting": {
                "clusterId": "carto-bt-cluster-c1",
                "allowTransactionalWrites": True,
            },
        },
    ],
}

MOCK_BACKUPS = {
    "backups": [
        {
            "name": "projects/test-project/instances/carto-bt-instance/clusters/carto-bt-cluster-c1/backups/carto-table-backup",
            "sourceTable": "projects/test-project/instances/carto-bt-instance/tables/carto-test-table",
            "expireTime": "2025-11-10T05:00:00Z",
            "startTime": "2025-11-03T05:00:00Z",
            "endTime": "2025-11-03T05:01:00Z",
            "sizeBytes": 123456789,
            "state": "READY",
        },
    ],
}


BIGTABLE_INSTANCE = [
    {
        'name': 'instance123',
        'id': 'instance123',
        'displayName': 'bigtableinst123',
        'state': 'READY',
        'type': 'PRODUCTION',
        'createTime': '2021-10-02T15:01:23Z',
    },
    {
        'name': 'instance456',
        'id': 'instance456',
        'displayName': 'bigtableinst456',
        'state': 'READY',
        'type': 'PRODUCTION',
        'createTime': '2021-10-02T15:01:23Z',
    },
]

BIGTABLE_CLUSTER = [
    {
        'name': 'cluster123',
        'instance_id': 'instance123',
        'id': 'cluster123',
        'location': 'us-east-1a',
        'state': 'READY',
        'serveNodes': 3,
        'defaultStorageType': 'SSD',
    },
    {
        'name': 'cluster456',
        'instance_id': 'instance456',
        'id': 'cluster456',
        'location': 'us-east-1a',
        'state': 'READY',
        'serveNodes': 3,
        'defaultStorageType': 'SSD',
    },
]

BIGTABLE_CLUSTER_BACKUP = [
    {
        'name': 'clusterbackup123',
        'id': 'clusterbackup123',
        'cluster_id': 'cluster123',
        'sourceTable': 'table123',
        'expireTime': '2021-09-02T15:01:23Z',
        'startTime': '2022-09-02T00:00:00Z',
        'endTime': '2021-12-31T00:00:00Z',
        'sizeBytes': '256GB',
        'state': 'READY',
    },
    {
        'name': 'clusterbackup456',
        'id': 'clusterbackup456',
        'cluster_id': 'cluster456',
        'sourceTable': 'table456',
        'expireTime': '2021-09-02T15:01:23Z',
        'startTime': '2022-09-02T00:00:00Z',
        'endTime': '2021-12-31T00:00:00Z',
        'sizeBytes': '256GB',
        'state': 'READY',
    },
]

BIGTABLE_TABLE = [
    {
        'name': 'table123',
        'id': 'table123',
        'instance_id': 'instance123',
        'replicationState': 'READY',
        'granularity': 'MILLIS',
        'sourceType': 'BACKUP',
    },
    {
        'name': 'table456',
        'id': 'table456',
        'instance_id': 'instance456',
        'replicationState': 'READY',
        'granularity': 'MILLIS',
        'sourceType': 'BACKUP',
    },
]
