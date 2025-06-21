from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from cartography.intel.gcp import containerregistry
from tests.data.gcp.containerregistry import ARTIFACT_REGISTRY_PACKAGES
from tests.data.gcp.containerregistry import ARTIFACT_REGISTRY_REPOSITORIES
from tests.data.gcp.containerregistry import ARTIFACT_REGISTRY_VERSIONS
from tests.data.gcp.containerregistry import GCP_LOCATIONS


@patch('cartography.intel.gcp.containerregistry.get_artifact_registry_client')
def test_get_artifact_registry_repositories(mock_get_client):
    # Arrange
    mock_client = MagicMock()
    mock_get_client.return_value = mock_client

    # Mock locations list
    mock_locations_list = MagicMock()
    mock_locations_list.execute.return_value = {'locations': GCP_LOCATIONS}
    mock_client.projects().locations().list.return_value = mock_locations_list

    # Mock repositories list
    mock_repo_list = MagicMock()
    mock_repo_list.execute.return_value = {'repositories': ARTIFACT_REGISTRY_REPOSITORIES}
    mock_client.projects().locations().repositories().list.return_value = mock_repo_list
    mock_client.projects().locations().repositories().list_next.return_value = None

    # Act
    result = containerregistry.get_artifact_registry_repositories(
        mock_client, 'test-project', None, {},
    )

    # Assert
    assert len(result) == 2
    assert result[0]['name'] == 'projects/test-project/locations/us-central1/repositories/my-repo'
    assert result[0]['format'] == 'DOCKER'
    assert result[0]['project_id'] == 'test-project'
    assert result[1]['name'] == 'projects/test-project/locations/europe-west1/repositories/python-repo'
    assert result[1]['format'] == 'PYTHON'


@patch('cartography.intel.gcp.containerregistry.get_container_registry_client')
def test_get_container_registry_repositories(mock_get_client):
    # Arrange
    mock_client = MagicMock()
    mock_get_client.return_value = mock_client

    # Mock repositories list to return 404 (no repositories found)
    from googleapiclient.discovery import HttpError
    mock_repo_list = MagicMock()
    mock_repo_list.execute.side_effect = HttpError(
        resp=MagicMock(status=404), content=b'Not Found',
    )
    mock_client.projects().locations().repositories().list.return_value = mock_repo_list

    # Act
    result = containerregistry.get_container_registry_repositories(
        mock_client, 'test-project', None, {},
    )

    # Assert
    assert len(result) == 3  # us, eu, asia
    assert all(repo['format'] == 'DOCKER' for repo in result)
    assert all('is_legacy_gcr' not in repo for repo in result)
    assert all(repo['project_id'] == 'test-project' for repo in result)


@patch('cartography.intel.gcp.containerregistry.get_artifact_registry_client')
def test_get_artifact_registry_packages(mock_get_client):
    # Arrange
    mock_client = MagicMock()
    mock_get_client.return_value = mock_client

    mock_package_list = MagicMock()
    mock_package_list.execute.return_value = {'packages': ARTIFACT_REGISTRY_PACKAGES}
    mock_client.projects().locations().repositories().packages().list.return_value = mock_package_list
    mock_client.projects().locations().repositories().packages().list_next.return_value = None

    # Act
    result = containerregistry.get_artifact_registry_packages(
        mock_client, 'test-project', 'us-central1', 'my-repo', {},
    )

    # Assert
    assert len(result) == 2
    assert result[0]['name'] == 'projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx'
    assert result[0]['project_id'] == 'test-project'
    assert result[0]['location'] == 'us-central1'
    assert result[0]['repository_name'] == 'my-repo'


@patch('cartography.intel.gcp.containerregistry.get_artifact_registry_client')
def test_get_artifact_registry_versions(mock_get_client):
    # Arrange
    mock_client = MagicMock()
    mock_get_client.return_value = mock_client

    mock_version_list = MagicMock()
    mock_version_list.execute.return_value = {'versions': ARTIFACT_REGISTRY_VERSIONS}
    mock_client.projects().locations().repositories().packages().versions().list.return_value = mock_version_list
    mock_client.projects().locations().repositories().packages().versions().list_next.return_value = None

    # Act
    result = containerregistry.get_artifact_registry_versions(
        mock_client, 'test-project', 'us-central1', 'my-repo', 'nginx', {},
    )

    # Assert
    assert len(result) == 2
    assert result[0]['name'] == 'projects/test-project/locations/us-central1/repositories/my-repo/packages/nginx/versions/1.21.0'
    assert result[0]['project_id'] == 'test-project'
    assert result[0]['location'] == 'us-central1'
    assert result[0]['repository_name'] == 'my-repo'
    assert result[0]['package_name'] == 'nginx'
    assert 'relatedTags' in result[0]
    assert 'metadata' in result[0]


def test_load_artifact_registry_repositories_tx(neo4j_session):
    # Arrange
    repositories = [
        {
            'name': 'test-repo-1',
            'display_name': 'Test Repository 1',
            'description': 'Test description',
            'format': 'DOCKER',
            'location': 'us-central1',
            'project_id': 'test-project',
            'create_time': '2023-01-01T00:00:00Z',
            'update_time': '2023-01-15T00:00:00Z',
            'kms_key_name': '',
            'size_bytes': 1024,
            'labels': {'env': 'test'},
            'console_link': 'https://console.cloud.google.com/...',
        },
    ]

    # Act
    containerregistry.load_artifact_registry_repositories(neo4j_session, 'test-project', repositories, 12345)

    # Assert
    nodes = neo4j_session.run(
        'MATCH (n:GCPArtifactRegistryRepository) RETURN n.name, n.format, n.project_id',
    ).data()
    assert len(nodes) == 1
    assert nodes[0]['n.name'] == 'test-repo-1'
    assert nodes[0]['n.format'] == 'DOCKER'
    assert nodes[0]['n.project_id'] == 'test-project'


def test_load_container_registry_repositories_tx(neo4j_session):
    # Arrange
    repositories = [
        {
            'name': 'gcr.io/test-project',
            'display_name': 'Container Registry - us',
            'description': 'Google Container Registry in us',
            'format': 'DOCKER',
            'location': 'us',
            'project_id': 'test-project',
            'create_time': '',
            'update_time': '',
            'kms_key_name': '',
            'size_bytes': 0,
            'labels': {},
            'console_link': 'https://console.cloud.google.com/...',
        },
    ]

    # Act
    containerregistry.load_container_registry_repositories(neo4j_session, 'test-project', repositories, 12345)

    # Assert
    nodes = neo4j_session.run(
        'MATCH (n:GCPContainerRegistryRepository) RETURN n.name, n.format, n.project_id',
    ).data()
    assert len(nodes) == 1
    assert nodes[0]['n.name'] == 'gcr.io/test-project'
    assert nodes[0]['n.format'] == 'DOCKER'
    assert nodes[0]['n.project_id'] == 'test-project'


def test_load_artifact_registry_packages_tx(neo4j_session):
    # Arrange
    # First create a repository
    neo4j_session.run(
        """
        CREATE (r:GCPArtifactRegistryRepository{name: 'test-repo'})
        """,
    )

    packages = [
        {
            'name': 'test-package-1',
            'display_name': 'Test Package 1',
            'create_time': '2023-01-01T00:00:00Z',
            'update_time': '2023-01-15T00:00:00Z',
            'project_id': 'test-project',
            'location': 'us-central1',
            'repository_name': 'test-repo',
        },
    ]

    # Act
    containerregistry.load_artifact_registry_packages(neo4j_session, 'test-repo', packages, 12345)

    # Assert
    nodes = neo4j_session.run(
        'MATCH (n:GCPArtifactRegistryPackage) RETURN n.name, n.project_id, n.repository_name',
    ).data()
    assert len(nodes) == 1
    assert nodes[0]['n.name'] == 'test-package-1'
    assert nodes[0]['n.project_id'] == 'test-project'
    assert nodes[0]['n.repository_name'] == 'test-repo'

    # Check relationship
    relationships = neo4j_session.run(
        'MATCH (r:GCPArtifactRegistryRepository)-[:CONTAINS_PACKAGE]->(p:GCPArtifactRegistryPackage) RETURN r.name, p.name',
    ).data()
    assert len(relationships) == 1
    assert relationships[0]['r.name'] == 'test-repo'
    assert relationships[0]['p.name'] == 'test-package-1'


def test_load_artifact_registry_versions_tx(neo4j_session):
    # Arrange
    # First create a package
    neo4j_session.run(
        """
        CREATE (p:GCPArtifactRegistryPackage{name: 'test-package'})
        """,
    )

    versions = [
        {
            'name': 'test-version-1',
            'description': 'Test Version 1',
            'create_time': '2023-01-01T00:00:00Z',
            'update_time': '2023-01-15T00:00:00Z',
            'related_tags': ['latest', 'stable'],
            'metadata': {'type': 'docker'},
            'project_id': 'test-project',
            'location': 'us-central1',
            'repository_name': 'test-repo',
            'package_name': 'test-package',
        },
    ]

    # Act
    containerregistry.load_artifact_registry_versions(neo4j_session, 'test-package', versions, 12345)

    # Assert
    nodes = neo4j_session.run(
        'MATCH (n:GCPArtifactRegistryVersion) RETURN n.name, n.project_id, n.package_name',
    ).data()
    assert len(nodes) == 1
    assert nodes[0]['n.name'] == 'test-version-1'
    assert nodes[0]['n.project_id'] == 'test-project'
    assert nodes[0]['n.package_name'] == 'test-package'

    # Check relationship
    relationships = neo4j_session.run(
        'MATCH (p:GCPArtifactRegistryPackage)-[:CONTAINS_VERSION]->(v:GCPArtifactRegistryVersion) RETURN p.name, v.name',
    ).data()
    assert len(relationships) == 1
    assert relationships[0]['p.name'] == 'test-package'
    assert relationships[0]['v.name'] == 'test-version-1'


@patch('cartography.intel.gcp.containerregistry.get_container_registry_client')
def test_get_container_registry_images(mock_get_client):
    # Arrange
    mock_client = MagicMock()
    mock_get_client.return_value = mock_client

    # Mock packages list
    mock_packages = [
        {'name': 'projects/test-project/locations/us/repositories/gcr.io/packages/nginx'},
        {'name': 'projects/test-project/locations/us/repositories/gcr.io/packages/app'},
    ]
    mock_package_list = MagicMock()
    mock_package_list.execute.return_value = {'packages': mock_packages}
    mock_client.projects().locations().repositories().packages().list.return_value = mock_package_list
    mock_client.projects().locations().repositories().packages().list_next.return_value = None

    # Mock versions list
    mock_versions = [
        {
            'name': 'projects/test-project/locations/us/repositories/gcr.io/packages/nginx/versions/1.21.0',
            'createTime': '2023-01-01T00:00:00Z',
            'updateTime': '2023-01-15T00:00:00Z',
            'relatedTags': ['latest', 'stable'],
            'metadata': {},
        },
    ]
    mock_version_list = MagicMock()
    mock_version_list.execute.return_value = {'versions': mock_versions}
    mock_client.projects().locations().repositories().packages().versions().list.return_value = mock_version_list
    mock_client.projects().locations().repositories().packages().versions().list_next.return_value = None

    # Act
    result = containerregistry.get_container_registry_images(
        mock_client, 'test-project', 'us', 'projects/test-project/locations/us/repositories/gcr.io', {},
    )

    # Assert
    assert len(result) >= 1
    assert result[0]['package_name'] == 'nginx'
    assert result[0]['project_id'] == 'test-project'
    assert result[0]['location'] == 'us'


def test_load_container_registry_images_tx(neo4j_session):
    # Arrange
    # First create a repository
    neo4j_session.run(
        """
        CREATE (r:GCPContainerRegistryRepository{name: 'test-repo'})
        """,
    )

    images = [
        {
            'name': 'test-image-1',
            'package_name': 'nginx',
            'repository_name': 'test-repo',
            'create_time': '2023-01-01T00:00:00Z',
            'update_time': '2023-01-15T00:00:00Z',
            'related_tags': ['latest', 'stable'],
            'metadata': {'type': 'docker'},
            'project_id': 'test-project',
            'location': 'us',
        },
    ]

    # Act
    containerregistry.load_container_registry_images(neo4j_session, 'test-repo', images, 12345)

    # Assert
    nodes = neo4j_session.run(
        'MATCH (n:GCPContainerRegistryImage) RETURN n.name, n.project_id, n.package_name',
    ).data()
    assert len(nodes) == 1
    assert nodes[0]['n.name'] == 'test-image-1'
    assert nodes[0]['n.project_id'] == 'test-project'
    assert nodes[0]['n.package_name'] == 'nginx'

    # Check relationship
    relationships = neo4j_session.run(
        'MATCH (r:GCPContainerRegistryRepository)-[:CONTAINS_IMAGE]->(i:GCPContainerRegistryImage) RETURN r.name, i.name',
    ).data()
    assert len(relationships) == 1
    assert relationships[0]['r.name'] == 'test-repo'
    assert relationships[0]['i.name'] == 'test-image-1'


@patch('cartography.intel.gcp.containerregistry.get_container_registry_client')
@patch('cartography.intel.gcp.containerregistry.get_artifact_registry_client')
@patch('cartography.intel.gcp.containerregistry.get_container_registry_repositories')
@patch('cartography.intel.gcp.containerregistry.get_artifact_registry_repositories')
@patch('cartography.intel.gcp.containerregistry.get_container_registry_images')
def test_sync_integration(
    mock_get_cr_images,
    mock_get_ar_repos,
    mock_get_cr_repos,
    mock_get_ar_client,
    mock_get_cr_client,
    neo4j_session,
):
    # Arrange
    mock_ar_client = MagicMock()
    mock_cr_client = MagicMock()
    mock_get_ar_client.return_value = mock_ar_client
    mock_get_cr_client.return_value = mock_cr_client

    # Mock Artifact Registry repositories
    ar_repos = [
        {
            'name': 'projects/test-project/locations/us-central1/repositories/my-repo',
            'display_name': 'My Repo',
            'description': 'Test repo',
            'format': 'DOCKER',
            'location': 'us-central1',
            'project_id': 'test-project',
            'create_time': '2023-01-01T00:00:00Z',
            'update_time': '2023-01-15T00:00:00Z',
            'kms_key_name': '',
            'size_bytes': 1024,
            'labels': {},
            'console_link': 'https://console.cloud.google.com/...',
        },
    ]
    mock_get_ar_repos.return_value = ar_repos

    # Mock Container Registry repositories
    cr_repos = [
        {
            'name': 'gcr.io/test-project',
            'display_name': 'Container Registry - us',
            'description': 'Google Container Registry in us',
            'format': 'DOCKER',
            'location': 'us',
            'project_id': 'test-project',
            'create_time': '',
            'update_time': '',
            'kms_key_name': '',
            'size_bytes': 0,
            'labels': {},
            'console_link': 'https://console.cloud.google.com/...',
        },
    ]
    mock_get_cr_repos.return_value = cr_repos

    # Mock Container Registry images
    cr_images = [
        {
            'name': 'projects/test-project/locations/us/repositories/gcr.io/packages/nginx/versions/1.21.0',
            'package_name': 'nginx',
            'repository_name': 'gcr.io/test-project',
            'create_time': '2023-01-01T00:00:00Z',
            'update_time': '2023-01-15T00:00:00Z',
            'related_tags': ['latest'],
            'metadata': {},
            'project_id': 'test-project',
            'location': 'us',
        },
    ]
    mock_get_cr_images.return_value = cr_images

    # Create a GCP project node first
    neo4j_session.run(
        """
        CREATE (p:GCPProject{id: 'test-project'})
        """,
    )

    # Act
    containerregistry.sync(
        neo4j_session,
        None,  # credentials
        'test-project',
        12345,  # update_tag
        {},  # common_job_parameters
        None,  # locations
    )

    # Assert
    ar_nodes = neo4j_session.run(
        'MATCH (n:GCPArtifactRegistryRepository) RETURN n.name, n.format ORDER BY n.name',
    ).data()
    assert len(ar_nodes) == 1
    assert ar_nodes[0]['n.name'] == 'projects/test-project/locations/us-central1/repositories/my-repo'
    assert ar_nodes[0]['n.format'] == 'DOCKER'

    cr_nodes = neo4j_session.run(
        'MATCH (n:GCPContainerRegistryRepository) RETURN n.name, n.format ORDER BY n.name',
    ).data()
    assert len(cr_nodes) == 1
    assert cr_nodes[0]['n.name'] == 'gcr.io/test-project'
    assert cr_nodes[0]['n.format'] == 'DOCKER'

    # Check relationships with GCP project
    ar_relationships = neo4j_session.run(
        'MATCH (p:GCPProject)-[:RESOURCE]->(r:GCPArtifactRegistryRepository) RETURN p.id, r.name',
    ).data()
    assert len(ar_relationships) == 1

    cr_relationships = neo4j_session.run(
        'MATCH (p:GCPProject)-[:RESOURCE]->(r:GCPContainerRegistryRepository) RETURN p.id, r.name',
    ).data()
    assert len(cr_relationships) == 1

    # Check Container Registry images
    cr_image_nodes = neo4j_session.run(
        'MATCH (n:GCPContainerRegistryImage) RETURN n.name, n.package_name ORDER BY n.name',
    ).data()
    assert len(cr_image_nodes) == 1
    assert cr_image_nodes[0]['n.package_name'] == 'nginx'

    # Check image relationships
    cr_image_relationships = neo4j_session.run(
        'MATCH (r:GCPContainerRegistryRepository)-[:CONTAINS_IMAGE]->(i:GCPContainerRegistryImage) RETURN r.name, i.package_name',
    ).data()
    assert len(cr_image_relationships) == 1
    assert cr_image_relationships[0]['i.package_name'] == 'nginx'
