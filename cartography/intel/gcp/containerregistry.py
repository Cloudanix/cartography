import json
import logging
import time
from typing import Dict
from typing import List
from urllib.parse import unquote

import neo4j
from cloudconsolelink.clouds.gcp import GCPLinker
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from . import label
from cartography.intel.gcp.util.errors import is_permission_error
from cartography.intel.gcp.util.errors import is_service_not_enabled_error
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
gcp_console_link = GCPLinker()

# Maximum page size of repositories.list; one call per location covers almost every project.
REPOSITORY_PAGE_SIZE = 1000
# Docker image history is unbounded (one image per CI push). Only the most recently updated images per repository
# are ingested, fetched in a single dockerImages.list page (max pageSize is 1000), so a repository costs exactly one
# call. 50 covers what is deployed plus a rollback window; older digests are history, not inventory.
MAX_IMAGES_PER_REPOSITORY = 50
IMAGES_ORDER_BY = 'update_time desc'
# Virtual repositories only re-expose images of their upstream repositories, which are listed on their own.
SKIP_IMAGE_REPOSITORY_MODES = {'VIRTUAL_REPOSITORY'}


def _http_error_details(e: HttpError) -> Dict:
    try:
        return json.loads(e.content.decode('utf-8')).get('error', {})
    except (AttributeError, UnicodeDecodeError, ValueError):
        return {}


def _is_permission_denied(e: HttpError, err: Dict) -> bool:
    # A disabled API also answers 403 PERMISSION_DENIED (reason SERVICE_DISABLED). Let that one raise: the GCP
    # dispatcher logs it at info as a skipped service instead of a permission warning per project.
    return is_permission_error(e, err) and not is_service_not_enabled_error(e)


@timeit
def get_artifact_registry_locations(artifacts: Resource, project_id: str) -> List[str]:
    """
    Locations Artifact Registry serves for the project. repositories.list takes a single location (a wildcard
    location is rejected with 400, googleapis/google-cloud-python#13529), so locations are listed once per project.
    A disabled API raises, and the GCP dispatcher skips the service quietly.
    """
    locations: List[str] = []
    try:
        request = artifacts.projects().locations().list(name=f"projects/{project_id}")
        while request is not None:
            response = request.execute()
            locations.extend(location['locationId'] for location in response.get('locations', []))
            request = artifacts.projects().locations().list_next(previous_request=request, previous_response=response)
        return locations
    except HttpError as e:
        err = _http_error_details(e)
        if _is_permission_denied(e, err):
            logger.warning(
                "Could not list Artifact Registry locations on project %s due to permissions issues. "
                "Code: %s, Message: %s",
                project_id, err.get('code'), err.get('message'),
            )
            return []
        raise


@timeit
def get_artifact_registry_repositories(artifacts: Resource, project_id: str, locations: List[str]) -> List[Dict]:
    repositories: List[Dict] = []
    try:
        for location in locations:
            request = artifacts.projects().locations().repositories().list(
                parent=f"projects/{project_id}/locations/{location}",
                pageSize=REPOSITORY_PAGE_SIZE,
            )
            while request is not None:
                response = request.execute()
                repositories.extend(response.get('repositories', []))
                request = artifacts.projects().locations().repositories().list_next(
                    previous_request=request, previous_response=response,
                )
        return repositories
    except HttpError as e:
        err = _http_error_details(e)
        if _is_permission_denied(e, err):
            logger.warning(
                "Could not list Artifact Registry repositories on project %s due to permissions issues. "
                "Code: %s, Message: %s",
                project_id, err.get('code'), err.get('message'),
            )
            return []
        raise


@timeit
def transform_artifact_registry_repositories(repositories: List[Dict], project_id: str) -> List[Dict]:
    """
    Neo4j stores only primitives and arrays of primitives: map-valued fields are reduced here (labels become
    GCPLabel nodes through label.sync_labels, cleanup policies a count) and never written to the node.
    """
    transformed = []
    for repo in repositories:
        # projects/<project>/locations/<location>/repositories/<repository>
        parts = repo['name'].split('/')
        region, name = parts[3], parts[5]
        transformed.append({
            'id': repo['name'],
            'name': name,
            'region': region,
            'project_id': project_id,
            'format': repo.get('format'),
            'mode': repo.get('mode'),
            'description': repo.get('description'),
            'create_time': repo.get('createTime'),
            'update_time': repo.get('updateTime'),
            'kms_key_name': repo.get('kmsKeyName'),
            # int64 fields come back as strings in the REST API
            'size_bytes': int(repo.get('sizeBytes', 0)),
            'registry_uri': repo.get('registryUri'),
            'immutable_tags': (repo.get('dockerConfig') or {}).get('immutableTags', False),
            'cleanup_policy_count': len(repo.get('cleanupPolicies') or {}),
            'cleanup_policy_dry_run': repo.get('cleanupPolicyDryRun', False),
            'vulnerability_scanning_state': (repo.get('vulnerabilityScanningConfig') or {}).get('enablementState'),
            'labels': repo.get('labels', {}),
            'consolelink': gcp_console_link.get_console_link(
                project_id=project_id, resource_name='artifact_registry_repository',
                region=region, instance_name=name, repository_format=repo.get('format'),
            ),
        })
    return transformed


@timeit
def load_artifact_registry_repositories(
    session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int,
) -> None:
    session.execute_write(load_artifact_registry_repositories_tx, data_list, project_id, update_tag)


@timeit
def load_artifact_registry_repositories_tx(
    tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int,
) -> None:
    query = """
    UNWIND $Records as record
    MERGE (repo:GCPArtifactRegistryRepository{id: record.id})
    ON CREATE SET
        repo.firstseen = timestamp()
    SET
        repo.lastupdated = $gcp_update_tag,
        repo.name = record.name,
        repo.region = record.region,
        repo.project_id = record.project_id,
        repo.format = record.format,
        repo.mode = record.mode,
        repo.description = record.description,
        repo.create_time = record.create_time,
        repo.update_time = record.update_time,
        repo.kms_key_name = record.kms_key_name,
        repo.size_bytes = record.size_bytes,
        repo.registry_uri = record.registry_uri,
        repo.immutable_tags = record.immutable_tags,
        repo.cleanup_policy_count = record.cleanup_policy_count,
        repo.cleanup_policy_dry_run = record.cleanup_policy_dry_run,
        repo.vulnerability_scanning_state = record.vulnerability_scanning_state,
        repo.consolelink = record.consolelink
    WITH repo
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(repo)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


@timeit
def cleanup_artifact_registry_repositories(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_artifact_registry_repositories_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def get_artifact_registry_docker_images(artifacts: Resource, repository: Dict) -> List[Dict]:
    """
    The MAX_IMAGES_PER_REPOSITORY most recently updated images of one DOCKER repository, in a single call.
    A WARNING names the repository when older images were left out.
    """
    try:
        response = artifacts.projects().locations().repositories().dockerImages().list(
            parent=repository['id'],
            pageSize=MAX_IMAGES_PER_REPOSITORY,
            orderBy=IMAGES_ORDER_BY,
        ).execute()
    except HttpError as e:
        err = _http_error_details(e)
        # Permission denied on one repository, or a repository deleted since it was listed: skip it only.
        if _is_permission_denied(e, err) or e.resp.status == 404:
            logger.warning(
                "Could not list docker images of Artifact Registry repository %s on project %s. Code: %s, Message: %s",
                repository['id'], repository['project_id'], err.get('code'), err.get('message'),
            )
            return []
        raise
    if response.get('nextPageToken'):
        logger.warning(
            "Artifact Registry repository %s on project %s has more docker images than the %s most recent ones "
            "ingested; older images are skipped.",
            repository['id'], repository['project_id'], MAX_IMAGES_PER_REPOSITORY,
        )
    return response.get('dockerImages', [])


@timeit
def transform_artifact_registry_docker_images(images: List[Dict], repository: Dict) -> List[Dict]:
    transformed = []
    for image in images:
        # <repository>/dockerImages/<url-encoded image path>@<digest>
        name = unquote(image['name'].split('/dockerImages/', 1)[1])
        image_name, _, digest = name.partition('@')
        transformed.append({
            'id': image['name'],
            'name': name,
            'image_name': image_name,
            'digest': digest,
            'uri': image.get('uri'),
            'tags': image.get('tags', []),
            # int64 fields come back as strings in the REST API
            'image_size_bytes': int(image.get('imageSizeBytes', 0)),
            'upload_time': image.get('uploadTime'),
            'build_time': image.get('buildTime'),
            'update_time': image.get('updateTime'),
            'media_type': image.get('mediaType'),
            'artifact_type': image.get('artifactType'),
            'region': repository['region'],
            'project_id': repository['project_id'],
            'repository_id': repository['id'],
        })
    return transformed


@timeit
def load_artifact_registry_docker_images(
    session: neo4j.Session, data_list: List[Dict], repository_id: str, update_tag: int,
) -> None:
    session.execute_write(load_artifact_registry_docker_images_tx, data_list, repository_id, update_tag)


@timeit
def load_artifact_registry_docker_images_tx(
    tx: neo4j.Transaction, data: List[Dict], repository_id: str, gcp_update_tag: int,
) -> None:
    query = """
    MATCH (repo:GCPArtifactRegistryRepository{id: $RepositoryId})
    UNWIND $Records as record
    MERGE (image:GCPArtifactRegistryDockerImage{id: record.id})
    ON CREATE SET
        image.firstseen = timestamp()
    SET
        image.lastupdated = $gcp_update_tag,
        image.name = record.name,
        image.image_name = record.image_name,
        image.digest = record.digest,
        image.uri = record.uri,
        image.tags = record.tags,
        image.image_size_bytes = record.image_size_bytes,
        image.upload_time = record.upload_time,
        image.build_time = record.build_time,
        image.update_time = record.update_time,
        image.media_type = record.media_type,
        image.artifact_type = record.artifact_type,
        image.region = record.region,
        image.project_id = record.project_id,
        image.repository_id = record.repository_id
    MERGE (repo)-[r:CONTAINS]->(image)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, RepositoryId=repository_id, gcp_update_tag=gcp_update_tag)


@timeit
def sync_artifact_registry_docker_images(
    neo4j_session: neo4j.Session, artifacts: Resource, repositories: List[Dict], gcp_update_tag: int,
) -> None:
    for repository in repositories:
        if repository['format'] != 'DOCKER' or repository['mode'] in SKIP_IMAGE_REPOSITORY_MODES:
            continue
        images = transform_artifact_registry_docker_images(
            get_artifact_registry_docker_images(artifacts, repository), repository,
        )
        load_artifact_registry_docker_images(neo4j_session, images, repository['id'], gcp_update_tag)


@timeit
def cleanup_artifact_registry_docker_images(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_artifact_registry_docker_images_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session,
    artifacts: Resource,
    project_id: str,
    gcp_update_tag: int,
    common_job_parameters: Dict,
    regions: list,
) -> None:
    """
    Sync Artifact Registry repositories of a project, plus the latest docker images of each DOCKER repository.
    API calls per project: 1 locations.list + 1 repositories.list per location (+1 per extra page of 1000
    repositories) + 1 dockerImages.list per DOCKER repository. gcr.io hosts are Artifact Registry repositories now
    (Container Registry is shut down), so there is no separate Container Registry API to call.
    `regions` (compute regions) is not used: repositories also live in multi-regions (us, europe, asia), so the
    locations come from the Artifact Registry API itself, like cloudtasks.
    """
    tic = time.perf_counter()
    logger.info("Syncing Artifact Registry for project '%s', at %s.", project_id, tic)

    locations = get_artifact_registry_locations(artifacts, project_id)
    repositories = transform_artifact_registry_repositories(
        get_artifact_registry_repositories(artifacts, project_id, locations), project_id,
    )
    load_artifact_registry_repositories(neo4j_session, repositories, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, repositories, gcp_update_tag, common_job_parameters,
        'artifact_registry_repositories', 'GCPArtifactRegistryRepository',
    )
    sync_artifact_registry_docker_images(neo4j_session, artifacts, repositories, gcp_update_tag)

    # Images first: their cleanup walks through the repository, which the repository cleanup may delete.
    cleanup_artifact_registry_docker_images(neo4j_session, common_job_parameters)
    cleanup_artifact_registry_repositories(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Artifact Registry: {toc - tic:0.4f} seconds")
