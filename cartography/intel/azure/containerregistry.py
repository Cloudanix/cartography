import json
import logging
import time
from datetime import datetime
from itertools import islice
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

import neo4j
from azure.core.exceptions import AzureError
from azure.core.exceptions import HttpResponseError
from azure.core.exceptions import ServiceRequestError
from azure.core.exceptions import ServiceResponseError
from azure.mgmt.containerregistry import ContainerRegistryManagementClient

from .util.console_link import safe_console_link
from .util.credentials import Credentials
from cartography.util import get_azure_resource_group_name
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

# AAD audience of the ACR data plane (the SDK default). Tokens for it are exchanged at
# https://<loginServer>/oauth2/exchange, so it works even when a registry disabled ARM-audience tokens.
ACR_DATA_PLANE_AUDIENCE = "https://containerregistry.azure.net"
# ACR serves 100 repository names per catalog page by default.
CATALOG_PAGE_SIZE = 100
# Manifests are unbounded push history (every CI push, every platform of a multi-arch image). Keep
# the most recently updated ones: they are what is deployed or about to be. 50 covers ~10-25 multi-arch
# releases and still fits one page, so a repository costs exactly one list call whatever N is.
MAX_MANIFESTS_PER_REPOSITORY = 50
# One manifest call per repository, so this caps the calls per registry (~500 + 6 catalog pages) and the
# graph (<= 25k images per registry). The catalog is alphabetical: past the cap, later names are dropped.
MAX_REPOSITORIES_PER_REGISTRY = 500
# Data-plane roles a registry must grant us before its repositories can be listed.
DATA_PLANE_ROLE_HINT = (
    "registries in 'RBAC Registry Permissions' mode need Reader (or AcrPull); ABAC-enabled registries need "
    "Container Registry Repository Reader + Container Registry Repository Catalog Lister"
)


def get_client(credentials: Credentials, subscription_id: str) -> ContainerRegistryManagementClient:
    from .util.timing import get_timing_policy
    client = ContainerRegistryManagementClient(credentials, subscription_id, per_call_policies=[get_timing_policy()])
    return client


def get_registry_client(credentials: Credentials, login_server: str) -> Any:
    """
    Data-plane client for one registry. Repositories and manifests are not on the management API.

    Imported here so a missing azure-containerregistry package fails only the "images" service.
    """
    from azure.containerregistry import ContainerRegistryClient

    from .util.timing import get_timing_policy
    return ContainerRegistryClient(
        f"https://{login_server}",
        credentials,
        audience=ACR_DATA_PLANE_AUDIENCE,
        per_call_policies=[get_timing_policy()],
    )


def get_registry_list(
    credentials: Credentials,
    subscription_id: str,
    regions: Optional[List[str]],
    common_job_parameters: Dict,
) -> List[Dict]:
    try:
        client = get_client(credentials, subscription_id)
        registries = []

        for registry in client.registries.list():
            if regions and registry.location not in regions:
                continue

            registry_dict = {
                "id": registry.id,
                "name": registry.name,
                "location": registry.location,
                "resource_group": get_azure_resource_group_name(registry.id),
                "login_server": registry.login_server,
                "sku_name": registry.sku.name if registry.sku else None,
                "sku_tier": registry.sku.tier if registry.sku else None,
                "admin_user_enabled": registry.admin_user_enabled,
                "public_network_access": registry.public_network_access,
                # Premium-only firewall; None (Basic / Standard) means every network is allowed.
                "network_rule_default_action": getattr(registry.network_rule_set, "default_action", None),
                "anonymous_pull_enabled": getattr(registry, "anonymous_pull_enabled", None),
                "zone_redundancy": registry.zone_redundancy,
                "encryption_status": registry.encryption.status if registry.encryption else None,
                "trust_policy_status": registry.policies.trust_policy.status
                if registry.policies and registry.policies.trust_policy
                else None,
                "quarantine_policy_status": registry.policies.quarantine_policy.status
                if registry.policies and registry.policies.quarantine_policy
                else None,
                "retention_policy_status": registry.policies.retention_policy.status
                if registry.policies and registry.policies.retention_policy
                else None,
                "creation_date": registry.creation_date.isoformat() if registry.creation_date else None,
                "console_link": safe_console_link(registry.id, common_job_parameters),
                "subscription_id": subscription_id,
                "type": registry.type,
                "tags": json.dumps(registry.tags) if registry.tags else None,
            }
            registries.append(registry_dict)

        return registries
    except HttpResponseError as e:
        logger.warning(f"Failed to retrieve container registries for subscription {subscription_id}: {e}")
        return []


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def _enum_value(value: Any) -> Optional[str]:
    # The SDK returns architecture/os as str enums; store the plain value.
    return getattr(value, "value", value)


def _first(items: Iterable, limit: int) -> Tuple[List, bool]:
    """The first `limit` items, and whether there were more. Stops paging right after item limit + 1."""
    head = list(islice(items, limit + 1))
    return head[:limit], len(head) > limit


def get_repository_list(client: Any, registry: Dict) -> Tuple[List[Dict], bool]:
    """
    List the registry's repositories from its catalog (GET /acr/v1/_catalog), at most
    MAX_REPOSITORIES_PER_REGISTRY of them.

    :return: the repositories, and whether the catalog had more
    :raises AzureError: on 401/403 (missing data-plane role, network rules) or when the registry is unreachable
    """
    names, truncated = _first(
        client.list_repository_names(results_per_page=CATALOG_PAGE_SIZE), MAX_REPOSITORIES_PER_REGISTRY,
    )
    repositories = []
    for name in names:
        repositories.append({
            "id": f"{registry['id']}/repositories/{name}",
            "name": name,
            "registry_id": registry["id"],
            "registry_name": registry["name"],
            "uri": f"{registry['login_server']}/{name}",
            "location": registry["location"],
            "resource_group": registry["resource_group"],
            "subscription_id": registry["subscription_id"],
            "console_link": registry.get("console_link"),
        })
    return repositories, truncated


def get_image_list(client: Any, repository: Dict) -> Tuple[List[Dict], bool]:
    """
    List the repository's MAX_MANIFESTS_PER_REPOSITORY most recently updated manifests
    (GET /acr/v1/<repo>/_manifests?orderby=timedesc&n=MAX+1: one call).

    :return: the images, newest first, and whether the repository has older ones
    :raises AzureError: on 401/403 or when the repository vanished between the catalog and this call
    """
    manifests, truncated = _first(
        client.list_manifest_properties(
            repository["name"], order_by="timedesc", results_per_page=MAX_MANIFESTS_PER_REPOSITORY + 1,
        ),
        MAX_MANIFESTS_PER_REPOSITORY,
    )
    images = []
    for manifest in manifests:
        images.append({
            "id": f"{repository['id']}@{manifest.digest}",
            "digest": manifest.digest,
            "name": f"{repository['name']}@{manifest.digest}",
            "uri": f"{repository['uri']}@{manifest.digest}",
            "repository_id": repository["id"],
            "repository_name": repository["name"],
            "registry_name": repository["registry_name"],
            "created_time": _iso(manifest.created_on),
            "last_update_time": _iso(manifest.last_updated_on),
            "architecture": _enum_value(manifest.architecture),
            "os": _enum_value(manifest.operating_system),
            "size": manifest.size_in_bytes,
            "size_bytes": manifest.size_in_bytes,
            "tags": list(manifest.tags or []),
            "location": repository["location"],
            "resource_group": repository["resource_group"],
            "subscription_id": repository["subscription_id"],
            "console_link": repository["console_link"],
        })
    return images, truncated


def _data_plane_error_reason(error: AzureError) -> str:
    status_code = getattr(error, "status_code", None)
    if status_code:
        return f"http_{status_code}"
    if isinstance(error, (ServiceRequestError, ServiceResponseError)):
        return "unreachable"
    return type(error).__name__


def _registry_skip_reason(registry: Dict) -> Optional[str]:
    if not registry.get("login_server"):
        return "no_login_server"
    # Only reachable through the customer's private endpoints, never from our scanner.
    if registry.get("public_network_access") == "Disabled":
        return "public_network_access_disabled"
    return None


def _load_registries_tx(tx: neo4j.Transaction, subscription_id: str, data_list: List[Dict], update_tag: int) -> None:
    ingest_query = """
    UNWIND $registries as registry
    MERGE (r:AzureContainerRegistry{id: registry.id})
    ON CREATE SET r.firstseen = timestamp()
    SET
        r.lastupdated = $update_tag,
        r.name = registry.name,
        r.location = registry.location,
        r.resource_group = registry.resource_group,
        r.login_server = registry.login_server,
        r.sku_name = registry.sku_name,
        r.sku_tier = registry.sku_tier,
        r.admin_user_enabled = registry.admin_user_enabled,
        r.public_network_access = registry.public_network_access,
        r.network_rule_default_action = registry.network_rule_default_action,
        r.anonymous_pull_enabled = registry.anonymous_pull_enabled,
        r.zone_redundancy = registry.zone_redundancy,
        r.encryption_status = registry.encryption_status,
        r.trust_policy_status = registry.trust_policy_status,
        r.quarantine_policy_status = registry.quarantine_policy_status,
        r.retention_policy_status = registry.retention_policy_status,
        r.creation_date = registry.creation_date,
        r.console_link = coalesce(registry.console_link, r.console_link),
        r.consolelink = coalesce(registry.console_link, r.consolelink),
        r.type = registry.type,
        r.tags = registry.tags

    WITH r
    MATCH (sub:AzureSubscription{id: $subscription_id})
    MERGE (sub)-[rel:RESOURCE]->(r)
    ON CREATE SET rel.firstseen = timestamp()
    SET rel.lastupdated = $update_tag
    """

    tx.run(
        ingest_query,
        registries=data_list,
        subscription_id=subscription_id,
        update_tag=update_tag,
    )


def _load_repositories_tx(tx: neo4j.Transaction, data_list: List[Dict], update_tag: int) -> None:
    ingest_query = """
    UNWIND $repositories as repo
    MERGE (r:AzureContainerRepository{id: repo.id})
    ON CREATE SET r.firstseen = timestamp()
    SET
        r.lastupdated = $update_tag,
        r.name = repo.name,
        r.registry_name = repo.registry_name,
        r.uri = repo.uri,
        r.location = repo.location,
        r.region = repo.location,
        r.resourcegroup = repo.resource_group,
        r.subscription_id = repo.subscription_id,
        r.last_update_time = repo.last_update_time,
        r.manifests_truncated = repo.manifests_truncated,
        r.type = 'Microsoft.ContainerRegistry/registries/repositories',
        r.consolelink = coalesce(repo.console_link, r.consolelink)

    WITH r, repo
    MATCH (reg:AzureContainerRegistry{id: repo.registry_id})
    MERGE (reg)-[rel:CONTAIN]->(r)
    ON CREATE SET rel.firstseen = timestamp()
    SET rel.lastupdated = $update_tag
    """

    tx.run(ingest_query, repositories=data_list, update_tag=update_tag)


def _load_images_tx(tx: neo4j.Transaction, data_list: List[Dict], update_tag: int) -> None:
    ingest_query = """
    UNWIND $images as image
    MERGE (i:AzureContainerImage{id: image.id})
    ON CREATE SET i.firstseen = timestamp()
    SET
        i.lastupdated = $update_tag,
        i.name = image.name,
        i.digest = image.digest,
        i.uri = image.uri,
        i.repository_name = image.repository_name,
        i.registry_name = image.registry_name,
        i.created_time = image.created_time,
        i.last_update_time = image.last_update_time,
        i.architecture = image.architecture,
        i.os = image.os,
        i.size = image.size,
        i.size_bytes = image.size_bytes,
        i.tags = image.tags,
        i.location = image.location,
        i.region = image.location,
        i.resourcegroup = image.resource_group,
        i.subscription_id = image.subscription_id,
        i.type = 'Microsoft.ContainerRegistry/registries/repositories/manifests',
        i.consolelink = coalesce(image.console_link, i.consolelink)

    WITH i, image
    MATCH (repo:AzureContainerRepository{id: image.repository_id})
    MERGE (repo)-[rel:CONTAIN]->(i)
    ON CREATE SET rel.firstseen = timestamp()
    SET rel.lastupdated = $update_tag
    """

    tx.run(ingest_query, images=data_list, update_tag=update_tag)


def _load_registry_fetch_status_tx(tx: neo4j.Transaction, registry_id: str, status: Dict) -> None:
    tx.run(
        "MATCH (r:AzureContainerRegistry{id: $registry_id}) SET r += $status",
        registry_id=registry_id,
        status=status,
    )


def load_registries(session: neo4j.Session, subscription_id: str, data_list: List[Dict], update_tag: int) -> None:
    session.execute_write(_load_registries_tx, subscription_id, data_list, update_tag)


def load_repositories(session: neo4j.Session, data_list: List[Dict], update_tag: int) -> None:
    session.execute_write(_load_repositories_tx, data_list, update_tag)


def load_images(session: neo4j.Session, data_list: List[Dict], update_tag: int) -> None:
    session.execute_write(_load_images_tx, data_list, update_tag)


def load_registry_fetch_status(session: neo4j.Session, registry_id: str, status: Dict) -> None:
    """
    Record on the registry whether its repositories could be read this sync, so a registry
    without repositories can be told apart from one we were not allowed to read.
    """
    session.execute_write(_load_registry_fetch_status_tx, registry_id, status)


def _fetch_status(
    fetched: bool, error: Optional[str] = None, repositories_truncated: bool = False, image_fetch_failures: int = 0,
) -> Dict:
    return {
        "repositories_fetched": fetched,
        "repositories_fetch_error": error,
        "repositories_truncated": repositories_truncated,
        "image_fetch_failures": image_fetch_failures,
    }


def _get_images(client: Any, repositories: List[Dict]) -> Tuple[Dict[str, List[Dict]], Dict[str, str]]:
    """
    Images per repository id, and the error reason per repository whose manifests could not be listed.
    Marks each listed repository with its newest update and whether older manifests were left out.
    """
    images_by_repository: Dict[str, List[Dict]] = {}
    failures: Dict[str, str] = {}
    for repository in repositories:
        try:
            images, truncated = get_image_list(client, repository)
        except AzureError as e:
            failures[repository["name"]] = _data_plane_error_reason(e)
            continue
        repository["manifests_truncated"] = truncated
        repository["last_update_time"] = images[0]["last_update_time"] if images else None
        images_by_repository[repository["id"]] = images
    return images_by_repository, failures


def _log_image_outcome(registry: Dict, repositories: List[Dict], failures: Dict[str, str]) -> None:
    if failures:
        logger.warning(
            "Could not list images of %d of %d repositories in container registry %s, e.g. %s",
            len(failures), len(repositories), registry["id"], next(iter(failures.items())),
        )
    truncated = sum(1 for r in repositories if r.get("manifests_truncated"))
    if truncated:
        logger.info(
            "Kept the %d most recent manifests of %d repositories in container registry %s",
            MAX_MANIFESTS_PER_REPOSITORY, truncated, registry["id"],
        )


def _sync_repositories(session: neo4j.Session, client: Any, registry: Dict, update_tag: int) -> Dict:
    try:
        repositories, truncated = get_repository_list(client, registry)
    except AzureError as e:
        reason = _data_plane_error_reason(e)
        logger.warning(
            "Skipping repositories of container registry %s (%s): %s. Data-plane read needs a role on the "
            "registry: %s.", registry["id"], reason, type(e).__name__, DATA_PLANE_ROLE_HINT,
        )
        return _fetch_status(False, reason)
    if truncated:
        logger.warning(
            "Container registry %s has more than %d repositories; ingesting the first %d in catalog order",
            registry["id"], MAX_REPOSITORIES_PER_REGISTRY, MAX_REPOSITORIES_PER_REGISTRY,
        )

    images_by_repository, failures = _get_images(client, repositories)
    load_repositories(session, repositories, update_tag)
    for images in images_by_repository.values():
        load_images(session, images, update_tag)
    _log_image_outcome(registry, repositories, failures)
    return _fetch_status(True, repositories_truncated=truncated, image_fetch_failures=len(failures))


def sync_registry_contents(
    session: neo4j.Session, credentials: Credentials, registry: Dict, update_tag: int,
) -> None:
    """
    Ingest the registry's repositories and images from its data plane. A registry we cannot read
    (no data-plane role, network rules, private-only) is skipped with one WARNING, never an error.
    """
    reason = _registry_skip_reason(registry)
    if reason:
        logger.info("Skipping repositories of container registry %s: %s", registry["id"], reason)
        load_registry_fetch_status(session, registry["id"], _fetch_status(False, reason))
        return
    client = get_registry_client(credentials, registry["login_server"])
    try:
        status = _sync_repositories(session, client, registry, update_tag)
    finally:
        client.close()
    load_registry_fetch_status(session, registry["id"], status)


def cleanup_container_registries(session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("azure_container_registries_cleanup.json", session, common_job_parameters)


def cleanup_container_repositories(session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("azure_container_repositories_cleanup.json", session, common_job_parameters)


def cleanup_container_images(session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("azure_container_images_cleanup.json", session, common_job_parameters)


@timeit
def sync(
    session: neo4j.Session,
    credentials: Credentials,
    subscription_id: str,
    update_tag: int,
    common_job_parameters: Dict,
    regions: Optional[List[str]] = None,
) -> None:
    logger.info("Syncing Azure Container Registries for subscription '%s'", subscription_id)
    tic = time.perf_counter()

    registries = get_registry_list(credentials, subscription_id, regions, common_job_parameters)
    load_registries(session, subscription_id, registries, update_tag)

    for registry in registries:
        logger.info(f"Syncing repositories for registry '{registry['name']}'")
        sync_registry_contents(session, credentials, registry, update_tag)

    # Children first: deleting a registry or repository detaches its children, and the
    # path-scoped statements could no longer reach them.
    cleanup_container_images(session, common_job_parameters)
    cleanup_container_repositories(session, common_job_parameters)
    cleanup_container_registries(session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process container registries: {toc - tic:0.4f} seconds")
