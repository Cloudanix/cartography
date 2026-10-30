import json
import logging
import re
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

import neo4j
from cloudconsolelink.clouds.gcp import GCPLinker
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from cartography.client.core.tx import load_graph_data
from cartography.client.core.tx import read_list_of_dicts_tx
from cartography.client.core.tx import run_write_query
from cartography.intel.gcp.util.errors import is_permission_error
from cartography.util import run_cleanup_job
from cartography.util import timeit

from . import label

logger = logging.getLogger(__name__)
gcp_console_link = GCPLinker()


def _image_partial_uri(source_image: Optional[str], project_id: Optional[str] = None) -> Optional[str]:
    """
    Normalize an image self-link or short reference to
    projects/{project}/global/images/{name} or
    projects/{project}/global/images/family/{family}.

    Same-project short forms (global/images/{name}) are expanded when project_id is known.
    """
    if not source_image:
        return None
    partial = source_image.strip()
    for marker in ("compute/v1/", "compute/beta/", "compute/alpha/"):
        if marker in partial:
            partial = partial.split(marker, 1)[1]
            break
    partial = partial.lstrip("/")
    if partial.startswith("http://") or partial.startswith("https://"):
        return None
    if partial.startswith("global/images/") and project_id:
        partial = f"projects/{project_id}/{partial}"
    if "/images/" not in partial:
        return None
    return partial or None


def _parse_image_reference(source_image: Optional[str], project_id: Optional[str] = None) -> Optional[Dict]:
    """Split an image reference into the owning project and a concrete name or a family."""
    partial = _image_partial_uri(source_image, project_id)
    if not partial:
        return None
    parts = partial.split("/")
    if len(parts) < 5 or parts[0] != "projects" or parts[2] != "global" or parts[3] != "images":
        return None
    image_project = parts[1]
    if not image_project:
        return None
    if len(parts) >= 6 and parts[4] == "family":
        family = parts[5]
        if not family:
            return None
        return {
            "project": image_project,
            "family": family,
            "name": None,
            "partial_uri": partial,
        }
    name = parts[4]
    if not name:
        return None
    return {
        "project": image_project,
        "family": None,
        "name": name,
        "partial_uri": f"projects/{image_project}/global/images/{name}",
    }


def _kms_key_name(key_obj: Optional[Dict]) -> Optional[str]:
    """Keep the Cloud KMS key resource name. Do not store raw key bytes."""
    if not isinstance(key_obj, dict):
        return None
    return key_obj.get("kmsKeyName")


def _string_list(values: Optional[List]) -> List[str]:
    if not values:
        return []
    return [str(value) for value in values if value is not None]


# Multi-region storageLocations are not Compute Engine regions. These are used only
# when the image has no disk zone. europe-west2 is the region id for London.
_MULTIREGION_FALLBACK = {
    "us": "us-central1",
    "eu": "europe-west2",
    "asia": "asia-south1",
}

_COMPUTE_REGION = re.compile(r"[a-z]+(?:-[a-z]+)+\d+")
_COMPUTE_ZONE = re.compile(r"[a-z]+(?:-[a-z]+)+\d+-[a-z]")


def _is_compute_region(value: str) -> bool:
    return _COMPUTE_REGION.fullmatch(value) is not None


def _region_from_zone(value: str) -> Optional[str]:
    if _COMPUTE_ZONE.fullmatch(value) is None:
        return None
    return value.rsplit("-", 1)[0]


def _region_from_compute_uri(uri: Optional[str]) -> Optional[str]:
    """Pull a region out of a zonal disk or regional snapshot URI."""
    if not uri:
        return None
    parts = uri.split("/")
    if "zones" in parts:
        zone = parts[parts.index("zones") + 1].lower()
        return _region_from_zone(zone)
    if "regions" in parts:
        region = parts[parts.index("regions") + 1].lower()
        if _is_compute_region(region):
            return region
    return None


def _region_from_disk_zone(zone: Optional[str]) -> Optional[str]:
    """Region of a disk zone, either a full Compute URI or a zone name like us-east1-b."""
    if not zone:
        return None
    from_uri = _region_from_compute_uri(zone)
    if from_uri:
        return from_uri
    return _region_from_zone(zone.strip().lower())


def _region_from_disk_zones(zones: List[str]) -> Optional[str]:
    """One region from the disk zones. The first zone name is used when several exist."""
    for zone in sorted(zone for zone in zones if zone):
        region = _region_from_disk_zone(zone)
        if region:
            return region
    return None


def _fallback_region(storage_locations: Optional[List]) -> Optional[str]:
    """Concrete region for a multi-region storage location, when no disk zone exists."""
    for location in _string_list(storage_locations):
        mapped = _MULTIREGION_FALLBACK.get(location.strip().lower())
        if mapped:
            return mapped
    return None


def _image_region(image: Dict) -> Optional[str]:
    """
    Region from the image itself, before disks created from it are considered.

    A storage location that is already a region, such as us-east1, is kept.
    A multi-region such as us uses the source disk zone. The multi-region
    fallback is not applied here, so a disk created from the image can still
    supply the zone. storage_locations still keeps the raw API value.
    """
    locations = [loc.strip().lower() for loc in _string_list(image.get("storageLocations"))]
    for location in locations:
        if location in _MULTIREGION_FALLBACK:
            continue
        if _is_compute_region(location):
            return location
        from_zone = _region_from_zone(location)
        if from_zone:
            return from_zone
    return _region_from_disk_zone(image.get("sourceDisk"))


def _region_for_image(image: Dict, disk_zones: Optional[List[str]] = None) -> Optional[str]:
    """
    Region stored on the image: a real storage region, then a disk zone, then
    the multi-region fallback.
    """
    region = _image_region(image)
    if region:
        return region
    from_disks = _region_from_disk_zones(disk_zones or [])
    if from_disks:
        return from_disks
    return _fallback_region(image.get("storageLocations"))


def transform_gcp_image(image: Dict, viewer_project_id: str) -> Optional[Dict]:
    """
    Flatten one Compute Engine image into properties stored on a GCPImage node.
    viewer_project_id is the project being synced and is used only for the console link.
    """
    self_link = image.get("selfLink") or ""
    name = image.get("name")
    partial = _image_partial_uri(self_link)
    if not partial and name:
        partial = f"projects/{viewer_project_id}/global/images/{name}"
    if not partial:
        return None

    owner_project = viewer_project_id
    if partial.startswith("projects/"):
        owner_project = partial.split("/")[1]

    deprecated = image.get("deprecated") or {}
    if not isinstance(deprecated, dict):
        deprecated = {}
    raw_disk = image.get("rawDisk") or {}
    if not isinstance(raw_disk, dict):
        raw_disk = {}
    guest_os = [
        feature.get("type")
        for feature in image.get("guestOsFeatures") or []
        if isinstance(feature, dict) and feature.get("type")
    ]
    labels = image.get("labels") or {}
    if not isinstance(labels, dict):
        labels = {}

    return {
        "id": partial,
        "partial_uri": partial,
        "image_id": str(image["id"]) if image.get("id") is not None else None,
        "name": name,
        "description": image.get("description"),
        "project_id": owner_project,
        "self_link": self_link or None,
        "creation_timestamp": image.get("creationTimestamp"),
        "status": image.get("status"),
        "source_type": image.get("sourceType"),
        "family": image.get("family"),
        "disk_size_gb": image.get("diskSizeGb"),
        "archive_size_bytes": image.get("archiveSizeBytes"),
        "architecture": image.get("architecture"),
        "licenses": image.get("licenses") or [],
        "license_codes": _string_list(image.get("licenseCodes")),
        "storage_locations": image.get("storageLocations") or [],
        "region": _image_region(image),
        "guest_os_features": guest_os,
        "os_features": "WINDOWS" if "WINDOWS" in guest_os else "LINUX",
        "source_disk": image.get("sourceDisk"),
        "source_disk_id": image.get("sourceDiskId"),
        "source_image": image.get("sourceImage"),
        "source_image_id": image.get("sourceImageId"),
        "source_snapshot": image.get("sourceSnapshot"),
        "source_snapshot_id": image.get("sourceSnapshotId"),
        "deprecated_state": deprecated.get("state"),
        "deprecated_replacement": deprecated.get("replacement"),
        "deprecated_deprecated": deprecated.get("deprecated"),
        "deprecated_obsolete": deprecated.get("obsolete"),
        "deprecated_deleted": deprecated.get("deleted"),
        "satisfies_pzs": image.get("satisfiesPzs"),
        "satisfies_pzi": image.get("satisfiesPzi"),
        "enable_confidential_compute": image.get("enableConfidentialCompute"),
        "label_fingerprint": image.get("labelFingerprint"),
        "has_shielded_instance_initial_state": bool(image.get("shieldedInstanceInitialState")),
        "raw_disk_source": raw_disk.get("source"),
        "raw_disk_container_type": raw_disk.get("containerType"),
        "raw_disk_sha1_checksum": raw_disk.get("sha1Checksum"),
        "image_encryption_kms_key": _kms_key_name(image.get("imageEncryptionKey")),
        "source_disk_encryption_kms_key": _kms_key_name(image.get("sourceDiskEncryptionKey")),
        "source_image_encryption_kms_key": _kms_key_name(image.get("sourceImageEncryptionKey")),
        "source_snapshot_encryption_kms_key": _kms_key_name(image.get("sourceSnapshotEncryptionKey")),
        "consolelink": gcp_console_link.get_console_link(
            resource_name="compute_image",
            project_id=viewer_project_id,
            image_name=name,
            image_project=owner_project,
        ) if name and viewer_project_id else None,
        "label_pairs": [f"{key}:{value}" for key, value in sorted(labels.items())],
        "labels": labels,
    }


def transform_gcp_images(images: List[Dict], viewer_project_id: str) -> List[Dict]:
    transformed = []
    for image in images:
        row = transform_gcp_image(image, viewer_project_id)
        if row:
            transformed.append(row)
    return transformed


def _permission_denied(error: HttpError) -> bool:
    try:
        err = json.loads(error.content.decode("utf-8"))["error"]
    except (UnicodeDecodeError, ValueError, KeyError, TypeError):
        return False
    return is_permission_error(error, err)


@timeit
def get_compute_images(compute: Resource, project_id: str) -> List[Dict]:
    """
    List Compute Engine images owned by the project.
    https://cloud.google.com/compute/docs/reference/rest/v1/images/list
    """
    images: List[Dict] = []
    try:
        request = compute.images().list(project=project_id)
        while request is not None:
            response = request.execute()
            images.extend(response.get("items") or [])
            request = compute.images().list_next(previous_request=request, previous_response=response)
        return images
    except HttpError as error:
        if _permission_denied(error):
            logger.warning(
                "Could not list Compute Engine images in project %s due to permissions: %s",
                project_id,
                error,
            )
            return []
        raise


def _fetch_compute_image(compute: Resource, ref: Dict) -> Optional[Dict]:
    """Fetch one concrete image, or the current image in a family. Missing images are skipped."""
    try:
        if ref.get("family"):
            request = compute.images().getFromFamily(project=ref["project"], family=ref["family"])
        else:
            request = compute.images().get(project=ref["project"], image=ref["name"])
        return request.execute()
    except HttpError as error:
        status = getattr(getattr(error, "resp", None), "status", None)
        if status in (403, 404) or _permission_denied(error):
            logger.warning(
                "Could not read Compute Engine image %s in project %s: %s",
                ref.get("family") or ref.get("name"),
                ref.get("project"),
                error,
            )
            return None
        raise


def resolve_referenced_images(
    compute: Resource,
    sources: List[str],
    known_ids: Set[str],
    project_id: str,
) -> Tuple[List[Dict], List[Dict]]:
    """
    Fetch images referenced by instances and disks that images.list did not return.

    Returns (raw_images, family_resolutions). A family resolution maps the family partial URI
    to the concrete image partial URI returned by getFromFamily.
    """
    raw_images: List[Dict] = []
    resolutions: List[Dict] = []
    seen: Set[str] = set()
    loaded = set(known_ids)

    for source in sources:
        ref = _parse_image_reference(source, project_id)
        if not ref or ref["partial_uri"] in seen:
            continue
        seen.add(ref["partial_uri"])
        if not ref["family"] and ref["partial_uri"] in loaded:
            continue

        image = _fetch_compute_image(compute, ref)
        if not image:
            continue
        concrete_id = _image_partial_uri(image.get("selfLink"))
        if not concrete_id and image.get("name"):
            concrete_id = f"projects/{ref['project']}/global/images/{image['name']}"
        if not concrete_id:
            continue
        if ref["family"]:
            resolutions.append({
                "source_partial_uri": ref["partial_uri"],
                "image_id": concrete_id,
                "family": ref["family"],
            })
        if concrete_id not in loaded:
            raw_images.append(image)
            loaded.add(concrete_id)
    return raw_images, resolutions


_LOAD_IMAGES_QUERY = """
UNWIND $DictList AS item
MERGE (img:GCPImage {id: item.id})
ON CREATE SET img.firstseen = timestamp()
SET
    img.partial_uri = item.partial_uri,
    img.image_id = item.image_id,
    img.name = item.name,
    img.description = item.description,
    img.project_id = item.project_id,
    img.self_link = item.self_link,
    img.creation_timestamp = item.creation_timestamp,
    img.status = item.status,
    img.source_type = item.source_type,
    img.family = item.family,
    img.disk_size_gb = item.disk_size_gb,
    img.archive_size_bytes = item.archive_size_bytes,
    img.architecture = item.architecture,
    img.licenses = item.licenses,
    img.license_codes = item.license_codes,
    img.storage_locations = item.storage_locations,
    img.region = item.region,
    img.guest_os_features = item.guest_os_features,
    img.os_features = item.os_features,
    img.source_disk = item.source_disk,
    img.source_disk_id = item.source_disk_id,
    img.source_image = item.source_image,
    img.source_image_id = item.source_image_id,
    img.source_snapshot = item.source_snapshot,
    img.source_snapshot_id = item.source_snapshot_id,
    img.deprecated_state = item.deprecated_state,
    img.deprecated_replacement = item.deprecated_replacement,
    img.deprecated_deprecated = item.deprecated_deprecated,
    img.deprecated_obsolete = item.deprecated_obsolete,
    img.deprecated_deleted = item.deprecated_deleted,
    img.satisfies_pzs = item.satisfies_pzs,
    img.satisfies_pzi = item.satisfies_pzi,
    img.enable_confidential_compute = item.enable_confidential_compute,
    img.label_fingerprint = item.label_fingerprint,
    img.has_shielded_instance_initial_state = item.has_shielded_instance_initial_state,
    img.raw_disk_source = item.raw_disk_source,
    img.raw_disk_container_type = item.raw_disk_container_type,
    img.raw_disk_sha1_checksum = item.raw_disk_sha1_checksum,
    img.image_encryption_kms_key = item.image_encryption_kms_key,
    img.source_disk_encryption_kms_key = item.source_disk_encryption_kms_key,
    img.source_image_encryption_kms_key = item.source_image_encryption_kms_key,
    img.source_snapshot_encryption_kms_key = item.source_snapshot_encryption_kms_key,
    img.consolelink = item.consolelink,
    img.label_pairs = item.label_pairs,
    img.lastupdated = $gcp_update_tag
WITH img, item
WHERE item.project_id = $ProjectId
MATCH (owner:GCPProject {id: $ProjectId})
MERGE (owner)-[r:RESOURCE]->(img)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $gcp_update_tag
"""


@timeit
def load_gcp_images(
    neo4j_session: neo4j.Session,
    images: List[Dict],
    project_id: str,
    gcp_update_tag: int,
) -> None:
    """
    Ingest GCPImage nodes. Images owned by the synced project are attached with RESOURCE.
    Images from other projects, such as public boot images, are stored but not owned here.
    """
    load_graph_data(
        neo4j_session,
        _LOAD_IMAGES_QUERY,
        images,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )


def _project_image_sources(neo4j_session: neo4j.Session, project_id: str) -> List[str]:
    query = """
    MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(n)
    WHERE (n:GCPInstance OR n:GCPComputeDisk) AND n.source_image IS NOT NULL
    RETURN DISTINCT n.source_image AS source_image
    """
    rows = neo4j_session.execute_read(
        read_list_of_dicts_tx,
        query,
        ProjectId=project_id,
    )
    return [row["source_image"] for row in rows if row.get("source_image")]


_LINK_DISKS_QUERY = """
MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(disk:GCPComputeDisk)
WHERE disk.image_partial_uri IS NOT NULL
MATCH (img:GCPImage {id: disk.image_partial_uri})
MERGE (disk)-[r:CREATED_FROM]->(img)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $gcp_update_tag
"""

_LINK_DISKS_BY_IMAGE_ID_QUERY = """
MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(disk:GCPComputeDisk)
WHERE disk.source_image_id IS NOT NULL
MATCH (img:GCPImage)
WHERE img.image_id = toString(disk.source_image_id)
MERGE (disk)-[r:CREATED_FROM]->(img)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $gcp_update_tag
"""

_LINK_INSTANCES_QUERY = """
MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(instance:GCPInstance)
WHERE instance.image_partial_uri IS NOT NULL
MATCH (img:GCPImage {id: instance.image_partial_uri})
MERGE (instance)-[r:HAS]->(img)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $gcp_update_tag
"""

_LINK_FAMILY_DISKS_QUERY = """
UNWIND $DictList AS row
MATCH (img:GCPImage {id: row.image_id})
MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(disk:GCPComputeDisk {image_partial_uri: row.source_partial_uri})
MERGE (disk)-[rel:CREATED_FROM]->(img)
ON CREATE SET rel.firstseen = timestamp()
SET rel.lastupdated = $gcp_update_tag,
    rel.via_family = row.family
WITH disk, row
OPTIONAL MATCH (disk)-[old:CREATED_FROM]->(stub:GCPImage {id: row.source_partial_uri})
WHERE stub.name IS NULL
DELETE old
"""

_LINK_FAMILY_INSTANCES_QUERY = """
UNWIND $DictList AS row
MATCH (img:GCPImage {id: row.image_id})
MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(instance:GCPInstance {image_partial_uri: row.source_partial_uri})
MERGE (instance)-[rel:HAS]->(img)
ON CREATE SET rel.firstseen = timestamp()
SET rel.lastupdated = $gcp_update_tag,
    rel.via_family = row.family
WITH instance, row
OPTIONAL MATCH (instance)-[old:HAS]->(stub:GCPImage {id: row.source_partial_uri})
WHERE stub.name IS NULL
DELETE old
"""

_IMAGE_DISK_ZONES_QUERY = """
MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(disk:GCPComputeDisk)-[:CREATED_FROM]->(img:GCPImage)
WHERE img.region IS NULL AND disk.zone IS NOT NULL
RETURN img.id AS image_id, collect(DISTINCT disk.zone) AS zones
"""

_SET_IMAGE_REGION_QUERY = """
UNWIND $DictList AS row
MATCH (img:GCPImage {id: row.image_id})
WHERE img.region IS NULL
SET img.region = row.region
"""

_DELETE_FAMILY_STUBS_QUERY = """
UNWIND $DictList AS row
MATCH (stub:GCPImage {id: row.source_partial_uri})
WHERE stub.name IS NULL AND NOT (stub)--()
DETACH DELETE stub
"""


def set_image_regions_from_disk_zones(neo4j_session: neo4j.Session, project_id: str) -> None:
    """
    Fill a missing image region from a disk created from that image.

    Used when storageLocations is a multi-region such as us and the image has
    no source disk of its own. The zone comes from GCPComputeDisk.zone.
    """
    rows = neo4j_session.execute_read(
        read_list_of_dicts_tx,
        _IMAGE_DISK_ZONES_QUERY,
        ProjectId=project_id,
    )
    records = []
    for row in rows:
        region = _region_from_disk_zones(row.get("zones") or [])
        if region and row.get("image_id"):
            records.append({"image_id": row["image_id"], "region": region})
    if not records:
        return
    load_graph_data(neo4j_session, _SET_IMAGE_REGION_QUERY, records)


_IMAGES_MISSING_REGION_QUERY = """
MATCH (img:GCPImage)
WHERE img.region IS NULL AND (
    EXISTS { MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(img) }
    OR EXISTS { MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(:GCPInstance)-[:HAS]->(img) }
    OR EXISTS { MATCH (:GCPProject {id: $ProjectId})-[:RESOURCE]->(:GCPComputeDisk)-[:CREATED_FROM]->(img) }
)
RETURN img.id AS image_id, img.storage_locations AS storage_locations
"""


def set_image_region_fallbacks(neo4j_session: neo4j.Session, project_id: str) -> None:
    """
    Set a concrete region when the image still has none after disk zones are checked.
    """
    rows = neo4j_session.execute_read(
        read_list_of_dicts_tx,
        _IMAGES_MISSING_REGION_QUERY,
        ProjectId=project_id,
    )
    records = []
    for row in rows:
        region = _fallback_region(row.get("storage_locations"))
        if region and row.get("image_id"):
            records.append({"image_id": row["image_id"], "region": region})
    if not records:
        return
    load_graph_data(neo4j_session, _SET_IMAGE_REGION_QUERY, records)


@timeit
def link_project_resources_to_images(
    neo4j_session: neo4j.Session,
    project_id: str,
    gcp_update_tag: int,
    family_resolutions: Optional[List[Dict]] = None,
) -> None:
    """
    Point disks and instances at GCPImage nodes.

    Concrete source URIs match the image partial URI. Image families are linked to the
    concrete image returned by getFromFamily. The family placeholder is removed once
    nothing else references it.
    """
    run_write_query(
        neo4j_session,
        _LINK_DISKS_QUERY,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )
    run_write_query(
        neo4j_session,
        _LINK_DISKS_BY_IMAGE_ID_QUERY,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )
    run_write_query(
        neo4j_session,
        _LINK_INSTANCES_QUERY,
        ProjectId=project_id,
        gcp_update_tag=gcp_update_tag,
    )
    if family_resolutions:
        load_graph_data(
            neo4j_session,
            _LINK_FAMILY_DISKS_QUERY,
            family_resolutions,
            ProjectId=project_id,
            gcp_update_tag=gcp_update_tag,
        )
        load_graph_data(
            neo4j_session,
            _LINK_FAMILY_INSTANCES_QUERY,
            family_resolutions,
            ProjectId=project_id,
            gcp_update_tag=gcp_update_tag,
        )
        load_graph_data(
            neo4j_session,
            _DELETE_FAMILY_STUBS_QUERY,
            family_resolutions,
            ProjectId=project_id,
            gcp_update_tag=gcp_update_tag,
        )
    set_image_regions_from_disk_zones(neo4j_session, project_id)
    set_image_region_fallbacks(neo4j_session, project_id)


@timeit
def cleanup_gcp_images(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("gcp_compute_images_cleanup.json", neo4j_session, common_job_parameters)


@timeit
def sync_compute_images(
    neo4j_session: neo4j.Session,
    compute: Resource,
    project_id: str,
    gcp_update_tag: int,
    common_job_parameters: Dict,
) -> Set[str]:
    """
    Load every Compute Engine image in the project and return their partial-URI ids.
    """
    raw_images = get_compute_images(compute, project_id)
    images = transform_gcp_images(raw_images, project_id)
    load_gcp_images(neo4j_session, images, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session,
        [image for image in images if image.get("project_id") == project_id],
        gcp_update_tag,
        common_job_parameters,
        "compute images",
        "GCPImage",
    )
    return {image["id"] for image in images if image.get("id")}


@timeit
def sync_referenced_compute_images(
    neo4j_session: neo4j.Session,
    compute: Resource,
    project_id: str,
    gcp_update_tag: int,
    known_ids: Set[str],
) -> None:
    """
    Load images that this project's instances and disks were created from, then link them.
    Runs after instance and disk sync so source_image is already on those nodes.
    """
    sources = _project_image_sources(neo4j_session, project_id)
    raw_images, resolutions = resolve_referenced_images(compute, sources, known_ids, project_id)
    images = transform_gcp_images(raw_images, project_id)
    load_gcp_images(neo4j_session, images, project_id, gcp_update_tag)
    link_project_resources_to_images(neo4j_session, project_id, gcp_update_tag, resolutions)
