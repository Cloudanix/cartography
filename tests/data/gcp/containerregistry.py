ARTIFACT_REGISTRY_REPOSITORIES = [
    {
        "name": "projects/test-project/locations/us-central1/repositories/my-repo",
        "displayName": "My Docker Repository",
        "description": "A sample Docker repository",
        "format": "DOCKER",
        "createTime": "2023-01-01T00:00:00Z",
        "updateTime": "2023-01-15T00:00:00Z",
        "kmsKeyName": "projects/test-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key",
        "sizeBytes": "1048576",
        "labels": {
            "env": "production",
            "team": "backend",
        },
    },
    {
        "name": "projects/test-project/locations/europe-west1/repositories/python-repo",
        "displayName": "Python Packages",
        "description": "Repository for Python packages",
        "format": "PYTHON",
        "createTime": "2023-02-01T00:00:00Z",
        "updateTime": "2023-02-15T00:00:00Z",
        "sizeBytes": "2097152",
        "labels": {
            "env": "development",
        },
    },
]

ARTIFACT_REGISTRY_PACKAGES = [
    {
        "name": "projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx",
        "displayName": "nginx",
        "createTime": "2023-01-01T00:00:00Z",
        "updateTime": "2023-01-15T00:00:00Z",
    },
    {
        "name": "projects/test-project/locations/us-central1/repositories/my-repo/packages/redis",
        "displayName": "redis",
        "createTime": "2023-01-05T00:00:00Z",
        "updateTime": "2023-01-20T00:00:00Z",
    },
]

ARTIFACT_REGISTRY_VERSIONS = [
    {
        "name": "projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx/versions/1.21.0",
        "description": "nginx version 1.21.0",
        "createTime": "2023-01-01T00:00:00Z",
        "updateTime": "2023-01-01T00:00:00Z",
        "relatedTags": [
            {
                "name": "projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx/tags/latest",
                "version": "projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx/versions/1.21.0",
            },
        ],
        "metadata": {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "schemaVersion": 2,
            "architecture": "amd64",
            "os": "linux",
        },
        "sizeBytes": "142857216",
    },
    {
        "name": "projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx/versions/1.20.0",
        "description": "nginx version 1.20.0",
        "createTime": "2022-12-01T00:00:00Z",
        "updateTime": "2022-12-01T00:00:00Z",
        "relatedTags": [
            {
                "name": "projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx/tags/stable",
                "version": "projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx/versions/1.20.0",
            },
        ],
        "metadata": {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "schemaVersion": 2,
            "architecture": "amd64",
            "os": "linux",
        },
        "sizeBytes": "89478485",
    },
]

GCP_LOCATIONS = [
    {
        "name": "projects/test-project/locations/us-central1",
        "locationId": "us-central1",
        "displayName": "Iowa",
        "labels": {},
        "metadata": {},
    },
    {
        "name": "projects/test-project/locations/europe-west1",
        "locationId": "europe-west1",
        "displayName": "Belgium",
        "labels": {},
        "metadata": {},
    },
]
