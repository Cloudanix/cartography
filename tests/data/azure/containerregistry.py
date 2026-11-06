from datetime import datetime
from datetime import timezone
from types import SimpleNamespace

REGISTRY_ID = '/subscriptions/sub-123/resourceGroups/rg-acr/providers/Microsoft.ContainerRegistry/registries/myregistry'

# Shaped like azure.mgmt.containerregistry Registry models (attribute access).
CONTAINER_REGISTRIES = [
    SimpleNamespace(
        id=REGISTRY_ID,
        name='myregistry',
        location='eastus',
        login_server='myregistry.azurecr.io',
        sku=SimpleNamespace(name='Premium', tier='Premium'),
        admin_user_enabled=True,
        public_network_access='Enabled',
        zone_redundancy='Enabled',
        encryption=SimpleNamespace(status='enabled'),
        policies=SimpleNamespace(
            trust_policy=SimpleNamespace(status='enabled'),
            quarantine_policy=SimpleNamespace(status='disabled'),
            retention_policy=SimpleNamespace(status='enabled'),
        ),
        creation_date=datetime(2021, 1, 15, 10, 30, tzinfo=timezone.utc),
        type='Microsoft.ContainerRegistry/registries',
        tags={'Environment': 'Production', 'Team': 'DevOps'},
    ),
    SimpleNamespace(
        id='/subscriptions/sub-123/resourceGroups/rg-acr/providers/Microsoft.ContainerRegistry/registries/testregistry',
        name='testregistry',
        location='westus2',
        login_server='testregistry.azurecr.io',
        sku=SimpleNamespace(name='Standard', tier='Standard'),
        admin_user_enabled=False,
        public_network_access='Disabled',
        zone_redundancy='Disabled',
        encryption=SimpleNamespace(status='disabled'),
        policies=SimpleNamespace(
            trust_policy=SimpleNamespace(status='disabled'),
            quarantine_policy=SimpleNamespace(status='enabled'),
            retention_policy=SimpleNamespace(status='disabled'),
        ),
        creation_date=datetime(2021, 6, 20, 14, 15, tzinfo=timezone.utc),
        type='Microsoft.ContainerRegistry/registries',
        tags={'Environment': 'Test'},
    ),
]

# Output of get_registry_list for the first registry above.
REGISTRY = {
    'id': REGISTRY_ID,
    'name': 'myregistry',
    'location': 'eastus',
    'resource_group': 'rg-acr',
    'login_server': 'myregistry.azurecr.io',
    'public_network_access': 'Enabled',
    'subscription_id': 'sub-123',
    'console_link': 'https://portal.azure.com/#@contoso.com/resource' + REGISTRY_ID,
}

REPOSITORY_NAMES = ['webapp', 'api-service']


def _arch(value: str) -> SimpleNamespace:
    # The data-plane SDK returns architecture/os as str enums with a .value
    return SimpleNamespace(value=value)


# Shaped like azure.containerregistry ArtifactManifestProperties, newest first.
MANIFESTS = [
    SimpleNamespace(
        digest='sha256:abc123def456',
        created_on=datetime(2021, 10, 15, 16, 30, tzinfo=timezone.utc),
        last_updated_on=datetime(2021, 10, 15, 16, 30, tzinfo=timezone.utc),
        architecture=_arch('amd64'),
        operating_system=_arch('linux'),
        size_in_bytes=134217728,
        tags=['latest', 'v1.2.3', 'stable'],
    ),
    SimpleNamespace(
        digest='sha256:def456ghi789',
        created_on=datetime(2021, 10, 10, 9, 20, tzinfo=timezone.utc),
        last_updated_on=datetime(2021, 10, 10, 9, 20, tzinfo=timezone.utc),
        architecture=_arch('arm64'),
        operating_system=_arch('linux'),
        size_in_bytes=67108864,
        tags=None,
    ),
]
