# Shapes follow the Artifact Registry v1 REST API (int64 fields are strings).
# https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories
# https://cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.dockerImages

GCP_LOCATIONS = [
    {"name": "projects/test-project/locations/us", "locationId": "us"},
    {"name": "projects/test-project/locations/us-central1", "locationId": "us-central1"},
    {"name": "projects/test-project/locations/europe-west1", "locationId": "europe-west1"},
]

ARTIFACT_REGISTRY_REPOSITORIES = [
    {
        "name": "projects/test-project/locations/us-central1/repositories/my-repo",
        "description": "A sample Docker repository",
        "format": "DOCKER",
        "mode": "STANDARD_REPOSITORY",
        "createTime": "2023-01-01T00:00:00Z",
        "updateTime": "2023-01-15T00:00:00Z",
        "kmsKeyName": "projects/test-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key",
        "sizeBytes": "1048576",
        "registryUri": "us-central1-docker.pkg.dev/test-project/my-repo",
        "labels": {
            "env": "production",
            "team": "backend",
        },
        "dockerConfig": {"immutableTags": True},
        "cleanupPolicies": {
            "delete-old": {"id": "delete-old", "action": "DELETE", "condition": {"olderThan": "2592000s"}},
        },
        "vulnerabilityScanningConfig": {"enablementConfig": "INHERITED", "enablementState": "SCANNING_ACTIVE"},
    },
    {
        # gcr.io host served by Artifact Registry after the Container Registry shutdown
        "name": "projects/test-project/locations/us/repositories/gcr.io",
        "format": "DOCKER",
        "mode": "STANDARD_REPOSITORY",
        "createTime": "2024-03-01T00:00:00Z",
        "updateTime": "2024-03-01T00:00:00Z",
        "sizeBytes": "0",
        "registryUri": "gcr.io/test-project",
    },
    {
        "name": "projects/test-project/locations/europe-west1/repositories/python-repo",
        "description": "Repository for Python packages",
        "format": "PYTHON",
        "mode": "STANDARD_REPOSITORY",
        "createTime": "2023-02-01T00:00:00Z",
        "updateTime": "2023-02-15T00:00:00Z",
        "sizeBytes": "2097152",
        "registryUri": "europe-west1-python.pkg.dev/test-project/python-repo",
        "labels": {
            "env": "development",
        },
    },
]
