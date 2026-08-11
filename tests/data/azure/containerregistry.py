from unittest.mock import Mock


CONTAINER_REGISTRIES = [
    {
        'id': '/subscriptions/sub-123/resourceGroups/rg-acr/providers/Microsoft.ContainerRegistry/registries/myregistry',
        'name': 'myregistry',
        'location': 'eastus',
        'login_server': 'myregistry.azurecr.io',
        'sku': Mock(name='Premium', tier='Premium'),
        'admin_user_enabled': True,
        'public_network_access': 'Enabled',
        'zone_redundancy': 'Enabled',
        'encryption': Mock(status='enabled'),
        'policies': Mock(
            trust_policy=Mock(status='enabled'),
            quarantine_policy=Mock(status='disabled'),
            retention_policy=Mock(status='enabled'),
        ),
        'creation_date': Mock(isoformat=lambda: '2021-01-15T10:30:00Z'),
        'type': 'Microsoft.ContainerRegistry/registries',
        'tags': {'Environment': 'Production', 'Team': 'DevOps'},
    },
    {
        'id': '/subscriptions/sub-123/resourceGroups/rg-acr/providers/Microsoft.ContainerRegistry/registries/testregistry',
        'name': 'testregistry',
        'location': 'westus2',
        'login_server': 'testregistry.azurecr.io',
        'sku': Mock(name='Standard', tier='Standard'),
        'admin_user_enabled': False,
        'public_network_access': 'Disabled',
        'zone_redundancy': 'Disabled',
        'encryption': Mock(status='disabled'),
        'policies': Mock(
            trust_policy=Mock(status='disabled'),
            quarantine_policy=Mock(status='enabled'),
            retention_policy=Mock(status='disabled'),
        ),
        'creation_date': Mock(isoformat=lambda: '2021-06-20T14:15:00Z'),
        'type': 'Microsoft.ContainerRegistry/registries',
        'tags': {'Environment': 'Test'},
    },
]


CONTAINER_REPOSITORIES = [
    {
        'name': 'webapp',
        'created_time': Mock(isoformat=lambda: '2021-02-01T08:00:00Z'),
        'last_update_time': Mock(isoformat=lambda: '2021-10-15T16:30:00Z'),
        'manifest_count': 25,
        'tag_count': 15,
        'size': 1073741824,  # 1GB
    },
    {
        'name': 'api-service',
        'created_time': Mock(isoformat=lambda: '2021-03-15T12:45:00Z'),
        'last_update_time': Mock(isoformat=lambda: '2021-10-10T09:20:00Z'),
        'manifest_count': 12,
        'tag_count': 8,
        'size': 536870912,  # 512MB
    },
]


CONTAINER_IMAGES = [
    {
        'digest': 'sha256:abc123def456',
        'created_time': Mock(isoformat=lambda: '2021-10-15T16:30:00Z'),
        'last_update_time': Mock(isoformat=lambda: '2021-10-15T16:30:00Z'),
        'architecture': 'amd64',
        'os': 'linux',
        'size': 134217728,  # 128MB
        'tags': ['latest', 'v1.2.3', 'stable'],
        'media_type': 'application/vnd.docker.distribution.manifest.v2+json',
        'config_media_type': 'application/vnd.docker.container.image.v1+json',
        'quarantine_state': 'Passed',
        'quarantine_details': '',
    },
    {
        'digest': 'sha256:def456ghi789',
        'created_time': Mock(isoformat=lambda: '2021-10-10T09:20:00Z'),
        'last_update_time': Mock(isoformat=lambda: '2021-10-10T09:20:00Z'),
        'architecture': 'arm64',
        'os': 'linux',
        'size': 67108864,  # 64MB
        'tags': ['v1.2.2', 'previous'],
        'media_type': 'application/vnd.docker.distribution.manifest.v2+json',
        'config_media_type': 'application/vnd.docker.container.image.v1+json',
        'quarantine_state': 'Passed',
        'quarantine_details': '',
    },
]
