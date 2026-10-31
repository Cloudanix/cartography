import logging
import time
from typing import Dict
from typing import List
from typing import Optional

import neo4j
from cloudconsolelink.clouds.gcp import GCPLinker
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
gcp_console_link = GCPLinker()


def get_artifact_registry_repositories(
    client: Resource,
    project_id: str,
    locations: Optional[List[str]],
    common_job_parameters: Dict,
) -> List[Dict]:
    try:
        repositories = []

        # If no locations specified, get all available locations
        if not locations:
            locations_req = client.projects().locations().list(name=f"projects/{project_id}")
            locations_result = locations_req.execute()
            locations = [loc["locationId"] for loc in locations_result.get("locations", [])]

        for location in locations:
            try:
                parent = f"projects/{project_id}/locations/{location}"
                req = client.projects().locations().repositories().list(parent=parent)

                while req:
                    result = req.execute()

                    if result.get("repositories"):
                        for repo in result["repositories"]:
                            consolelink = gcp_console_link.get_console_link(
                                project_id=project_id,
                                resource_name="artifact_registry_repository",
                                region=location,
                                instance_name=repo["name"].split("/")[-1],
                                repository_format=repo.get("format"),
                            )
                            repo_dict = {
                                "name": repo["name"],
                                "display_name": repo.get("displayName", ""),
                                "description": repo.get("description", ""),
                                "format": repo.get("format", ""),
                                "location": location,
                                "project_id": project_id,
                                "create_time": repo.get("createTime", ""),
                                "update_time": repo.get("updateTime", ""),
                                "kms_key_name": repo.get("kmsKeyName", ""),
                                "size_bytes": repo.get("sizeBytes", 0),
                                "labels": repo.get("labels", {}),
                                "consolelink": consolelink,
                                # console_link kept for readers of the old property name
                                "console_link": consolelink,
                            }
                            repositories.append(repo_dict)

                    req = client.projects().locations().repositories().list_next(req, result)

            except HttpError as e:
                if e.resp.status == 403:
                    logger.warning(f"Access denied for Artifact Registry in location {location}: {e}")
                else:
                    logger.warning(f"Failed to retrieve Artifact Registry repositories in {location}: {e}")

        return repositories

    except HttpError as e:
        logger.warning(f"Failed to retrieve Artifact Registry repositories for project {project_id}: {e}")
        return []


def get_artifact_registry_packages(
    client: Resource,
    project_id: str,
    location: str,
    repository_name: str,
    common_job_parameters: Dict,
) -> List[Dict]:
    try:
        packages = []
        parent = f"projects/{project_id}/locations/{location}/repositories/{repository_name}"

        req = client.projects().locations().repositories().packages().list(parent=parent)

        while req:
            result = req.execute()

            if result.get("packages"):
                for package in result["packages"]:
                    package_dict = {
                        "name": package["name"],
                        "display_name": package.get("displayName", ""),
                        "create_time": package.get("createTime", ""),
                        "update_time": package.get("updateTime", ""),
                        "project_id": project_id,
                        "location": location,
                        "repository_name": repository_name,
                    }
                    packages.append(package_dict)

            req = client.projects().locations().repositories().packages().list_next(req, result)

        return packages

    except HttpError as e:
        logger.warning(f"Failed to retrieve packages for repository {repository_name}: {e}")
        return []


def get_artifact_registry_versions(
    client: Resource,
    project_id: str,
    location: str,
    repository_name: str,
    package_name: str,
    common_job_parameters: Dict,
) -> List[Dict]:
    try:
        versions = []
        parent = f"projects/{project_id}/locations/{location}/repositories/{repository_name}/packages/{package_name}"

        req = client.projects().locations().repositories().packages().versions().list(parent=parent)

        while req:
            result = req.execute()

            if result.get("versions"):
                for version in result["versions"]:
                    version_dict = {
                        "name": version["name"],
                        "description": version.get("description", ""),
                        "create_time": version.get("createTime", ""),
                        "update_time": version.get("updateTime", ""),
                        "related_tags": version.get("relatedTags", []),
                        "metadata": version.get("metadata", {}),
                        "size_bytes": version.get("sizeBytes", 0),
                        "digest": version.get("name", "").split("/")[-1]
                        if "@sha256:" in version.get("name", "")
                        else "",
                        "architecture": version.get("metadata", {}).get("architecture", ""),
                        "os": version.get("metadata", {}).get("os", ""),
                        "project_id": project_id,
                        "location": location,
                        "repository_name": repository_name,
                        "package_name": package_name,
                    }
                    versions.append(version_dict)

            req = client.projects().locations().repositories().packages().versions().list_next(req, result)

        return versions

    except HttpError as e:
        logger.warning(f"Failed to retrieve versions for package {package_name}: {e}")
        return []


def _load_artifact_registry_repositories_tx(
    tx: neo4j.Transaction,
    project_id: str,
    data_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_query = """
    UNWIND $repositories as repo
    MERGE (r:GCPArtifactRegistryRepository{name: repo.name})
    ON CREATE SET r.firstseen = timestamp()
    SET
        r.lastupdated = $update_tag,
        r.display_name = repo.display_name,
        r.description = repo.description,
        r.format = repo.format,
        r.location = repo.location,
        r.project_id = repo.project_id,
        r.create_time = repo.create_time,
        r.update_time = repo.update_time,
        r.kms_key_name = repo.kms_key_name,
        r.size_bytes = repo.size_bytes,
        r.labels = repo.labels,
        r.consolelink = repo.consolelink,
        r.console_link = repo.console_link

    WITH r
    MATCH (p:GCPProject{id: $project_id})
    MERGE (p)-[rel:RESOURCE]->(r)
    ON CREATE SET rel.firstseen = timestamp()
    SET rel.lastupdated = $update_tag
    """

    tx.run(
        ingest_query,
        repositories=data_list,
        project_id=project_id,
        update_tag=update_tag,
    )


def _load_artifact_registry_packages_tx(
    tx: neo4j.Transaction,
    repository_name: str,
    data_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_query = """
    UNWIND $packages as pkg
    MERGE (p:GCPArtifactRegistryPackage{name: pkg.name})
    ON CREATE SET p.firstseen = timestamp()
    SET
        p.lastupdated = $update_tag,
        p.display_name = pkg.display_name,
        p.create_time = pkg.create_time,
        p.update_time = pkg.update_time,
        p.project_id = pkg.project_id,
        p.location = pkg.location,
        p.repository_name = pkg.repository_name

    WITH p
    MATCH (r:GCPArtifactRegistryRepository{name: $repository_name})
    MERGE (r)-[rel:CONTAINS]->(p)
    ON CREATE SET rel.firstseen = timestamp()
    SET rel.lastupdated = $update_tag
    """

    tx.run(
        ingest_query,
        packages=data_list,
        repository_name=repository_name,
        update_tag=update_tag,
    )


def _load_artifact_registry_versions_tx(
    tx: neo4j.Transaction,
    package_name: str,
    data_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_query = """
    UNWIND $versions as ver
    MERGE (v:GCPArtifactRegistryVersion{name: ver.name})
    ON CREATE SET v.firstseen = timestamp()
    SET
        v.lastupdated = $update_tag,
        v.description = ver.description,
        v.create_time = ver.create_time,
        v.update_time = ver.update_time,
        v.related_tags = ver.related_tags,
        v.metadata = ver.metadata,
        v.size_bytes = ver.size_bytes,
        v.digest = ver.digest,
        v.architecture = ver.architecture,
        v.os = ver.os,
        v.project_id = ver.project_id,
        v.location = ver.location,
        v.repository_name = ver.repository_name,
        v.package_name = ver.package_name

    WITH v
    MATCH (p:GCPArtifactRegistryPackage{name: $package_name})
    MERGE (p)-[rel:CONTAINS]->(v)
    ON CREATE SET rel.firstseen = timestamp()
    SET rel.lastupdated = $update_tag
    """

    tx.run(
        ingest_query,
        versions=data_list,
        package_name=package_name,
        update_tag=update_tag,
    )


def load_artifact_registry_repositories(
    session: neo4j.Session,
    project_id: str,
    data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(_load_artifact_registry_repositories_tx, project_id, data_list, update_tag)


def load_artifact_registry_packages(
    session: neo4j.Session,
    repository_name: str,
    data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(_load_artifact_registry_packages_tx, repository_name, data_list, update_tag)


def load_artifact_registry_versions(
    session: neo4j.Session,
    package_name: str,
    data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(_load_artifact_registry_versions_tx, package_name, data_list, update_tag)


def cleanup_artifact_registry_repositories(session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("gcp_artifact_registry_repositories_cleanup.json", session, common_job_parameters)


def cleanup_artifact_registry_packages(session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("gcp_artifact_registry_packages_cleanup.json", session, common_job_parameters)


def cleanup_artifact_registry_versions(session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("gcp_artifact_registry_versions_cleanup.json", session, common_job_parameters)


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
    Sync Artifact Registry repositories of a project. gcr.io hosts are Artifact Registry repositories now
    (Container Registry is shut down), so there is no separate Container Registry API to call.
    `regions` (compute regions) is not used: repositories also live in multi-regions (us, europe, asia), so the
    locations come from the Artifact Registry API itself, like cloudtasks.
    """
    logger.info("Syncing GCP Artifact Registry for project '%s'", project_id)
    tic = time.perf_counter()

    artifact_repositories = get_artifact_registry_repositories(
        artifacts,
        project_id,
        None,
        common_job_parameters,
    )

    load_artifact_registry_repositories(neo4j_session, project_id, artifact_repositories, gcp_update_tag)

    # Sync packages and versions for Artifact Registry repositories only
    for repository in artifact_repositories:
        repo_name = repository["name"].split("/")[-1]
        logger.info(f"Syncing packages for repository '{repo_name}'")

        packages = get_artifact_registry_packages(
            artifacts,
            project_id,
            repository["location"],
            repo_name,
            common_job_parameters,
        )
        load_artifact_registry_packages(neo4j_session, repository["name"], packages, gcp_update_tag)

        for package in packages:
            pkg_name = package["name"].split("/")[-1]
            logger.info(f"Syncing versions for package '{pkg_name}'")

            versions = get_artifact_registry_versions(
                artifacts,
                project_id,
                repository["location"],
                repo_name,
                pkg_name,
                common_job_parameters,
            )
            load_artifact_registry_versions(neo4j_session, package["name"], versions, gcp_update_tag)

    cleanup_artifact_registry_repositories(neo4j_session, common_job_parameters)
    cleanup_artifact_registry_packages(neo4j_session, common_job_parameters)
    cleanup_artifact_registry_versions(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process GCP Artifact Registry: {toc - tic:0.4f} seconds")
