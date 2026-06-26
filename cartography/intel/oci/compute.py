# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI Compute API-centric functions
# https://docs.cloud.oracle.com/iaas/Content/Compute/Concepts/computeoverview.htm
import logging
import time
from typing import Any
from typing import Dict
from typing import List

import neo4j
import oci
import oci.core
import oci.identity

from . import utils
from cartography.client.core.tx import load_graph_data
from cartography.util import run_cleanup_job

logger = logging.getLogger(__name__)


def get_instance_list_data(
    compute: oci.core.compute_client.ComputeClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all compute instances in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/Instance/ListInstances
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            compute.list_instances, compartment_id=compartment_id,
        )
        return {'Instances': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve compute instances for compartment '%s': %s", compartment_id, e.message,
        )
        return {'Instances': []}


def load_instances(
    neo4j_session: neo4j.Session,
    instances: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Compute Instance data into Neo4j.
    """
    ingest_instance = """
    UNWIND $DictList AS instance
        MERGE (inode:OCIInstance{id: instance.ocid})
        ON CREATE SET inode.firstseen = timestamp(),
        inode.createdate = instance.time_created
        SET inode.ocid = instance.ocid,
        inode.display_name = instance.display_name,
        inode.compartment_id = instance.compartment_id,
        inode.resource_type = 'oci-compute-vm-instance',
        inode.availability_domain = instance.availability_domain,
        inode.fault_domain = instance.fault_domain,
        inode.shape = instance.shape,
        inode.lifecycle_state = instance.lifecycle_state,
        inode.region = $REGION,
        inode.image_id = instance.image_id,
        inode.are_legacy_imds_endpoints_disabled = instance.are_legacy_imds_endpoints_disabled,
        inode.is_secure_boot_enabled = instance.is_secure_boot_enabled,
        inode.is_pv_encryption_in_transit_enabled = instance.is_pv_encryption_in_transit_enabled,
        inode.is_monitoring_disabled = instance.is_monitoring_disabled,
        inode.lastupdated = $oci_update_tag
        WITH inode, instance
        MATCH (cc:OCICompartment{id: instance.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(inode)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = []
    for instance in instances:
        # Nested config objects (may be absent depending on shape/image).
        instance_options = instance.get("instance-options", {}) or {}
        platform_config = instance.get("platform-config", {}) or {}
        launch_options = instance.get("launch-options", {}) or {}
        agent_config = instance.get("agent-config", {}) or {}

        rows.append({
            "ocid": instance.get("id"),
            "display_name": instance.get("display-name"),
            "compartment_id": instance.get("compartment-id", compartment_id),
            "availability_domain": instance.get("availability-domain"),
            "fault_domain": instance.get("fault-domain"),
            "shape": instance.get("shape"),
            "lifecycle_state": instance.get("lifecycle-state"),
            "image_id": instance.get("image-id"),
            "are_legacy_imds_endpoints_disabled": instance_options.get("are-legacy-imds-endpoints-disabled"),
            "is_secure_boot_enabled": platform_config.get("is-secure-boot-enabled"),
            "is_pv_encryption_in_transit_enabled": launch_options.get("is-pv-encryption-in-transit-enabled"),
            "is_monitoring_disabled": agent_config.get("is-monitoring-disabled"),
            "time_created": str(instance.get("time-created", "")),
        })

    load_graph_data(
        neo4j_session, ingest_instance, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def get_vnic_attachment_list_data(
    compute: oci.core.compute_client.ComputeClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all VNIC attachments in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/VnicAttachment/ListVnicAttachments
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            compute.list_vnic_attachments, compartment_id=compartment_id,
        )
        return {'VnicAttachments': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve VNIC attachments for compartment '%s': %s", compartment_id, e.message,
        )
        return {'VnicAttachments': []}


def load_vnic_attachments(
    neo4j_session: neo4j.Session,
    vnic_attachments: List[Dict[str, Any]],
    tenancy_id: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI VNIC Attachment data into Neo4j and link to instances.
    """
    ingest_vnic_attachment = """
    UNWIND $DictList AS att
        MERGE (vnic:OCIVnicAttachment{id: att.ocid})
        ON CREATE SET vnic.firstseen = timestamp(),
        vnic.createdate = att.time_created
        SET vnic.ocid = att.ocid,
        vnic.display_name = att.display_name,
        vnic.compartment_id = att.compartment_id,
        vnic.availability_domain = att.availability_domain,
        vnic.lifecycle_state = att.lifecycle_state,
        vnic.vnic_id = att.vnic_id,
        vnic.subnet_id = att.subnet_id,
        vnic.nic_index = att.nic_index,
        vnic.lastupdated = $oci_update_tag
        WITH vnic, att
        MATCH (inode:OCIInstance{id: att.instance_id})
        MERGE (inode)-[r:OCI_VNIC_ATTACHMENT]->(vnic)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": attachment.get("id"),
            "display_name": attachment.get("display-name"),
            "compartment_id": attachment.get("compartment-id"),
            "availability_domain": attachment.get("availability-domain"),
            "lifecycle_state": attachment.get("lifecycle-state"),
            "vnic_id": attachment.get("vnic-id"),
            "subnet_id": attachment.get("subnet-id"),
            "nic_index": attachment.get("nic-index"),
            "instance_id": attachment.get("instance-id"),
            "time_created": str(attachment.get("time-created", "")),
        }
        for attachment in vnic_attachments
    ]
    load_graph_data(
        neo4j_session, ingest_vnic_attachment, rows,
        oci_update_tag=oci_update_tag,
    )


def get_image_list_data(
    compute: oci.core.compute_client.ComputeClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all images in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/Image/ListImages
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            compute.list_images, compartment_id=compartment_id,
        )
        return {'Images': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve images for compartment '%s': %s", compartment_id, e.message,
        )
        return {'Images': []}


def load_images(
    neo4j_session: neo4j.Session,
    images: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Image data into Neo4j.
    """
    ingest_image = """
    UNWIND $DictList AS image
        MERGE (img:OCIImage{id: image.ocid})
        ON CREATE SET img.firstseen = timestamp(),
        img.createdate = image.time_created
        SET img.ocid = image.ocid,
        img.display_name = image.display_name,
        img.compartment_id = image.compartment_id,
        img.operating_system = image.operating_system,
        img.operating_system_version = image.operating_system_version,
        img.lifecycle_state = image.lifecycle_state,
        img.size_in_mbs = image.size_in_mbs,
        img.lastupdated = $oci_update_tag
        WITH img, image
        MATCH (cc:OCICompartment{id: image.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(img)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": image.get("id"),
            "display_name": image.get("display-name"),
            "compartment_id": image.get("compartment-id") if image.get("compartment-id") else compartment_id,
            "operating_system": image.get("operating-system"),
            "operating_system_version": image.get("operating-system-version"),
            "lifecycle_state": image.get("lifecycle-state"),
            "size_in_mbs": image.get("size-in-mbs"),
            "time_created": str(image.get("time-created", "")),
        }
        for image in images
    ]
    load_graph_data(
        neo4j_session, ingest_image, rows,
        oci_update_tag=oci_update_tag,
    )


def get_boot_volume_attachment_list_data(
    compute: oci.core.compute_client.ComputeClient,
    availability_domain: str,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all boot volume attachments in a compartment for a given availability domain.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/BootVolumeAttachment/ListBootVolumeAttachments
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            compute.list_boot_volume_attachments,
            availability_domain=availability_domain,
            compartment_id=compartment_id,
        )
        return {'BootVolumeAttachments': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve boot volume attachments for compartment '%s', AD '%s': %s",
            compartment_id, availability_domain, e.message,
        )
        return {'BootVolumeAttachments': []}


def load_boot_volume_attachments(
    neo4j_session: neo4j.Session,
    boot_volume_attachments: List[Dict[str, Any]],
    tenancy_id: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Boot Volume Attachment data into Neo4j and link to instances.
    """
    ingest_boot_volume_attachment = """
    UNWIND $DictList AS att
        MERGE (bva:OCIBootVolumeAttachment{id: att.bva_id})
        ON CREATE SET bva.firstseen = timestamp(),
        bva.createdate = att.time_created
        SET bva.ocid = att.ocid,
        bva.display_name = att.display_name,
        bva.compartment_id = att.compartment_id,
        bva.availability_domain = att.availability_domain,
        bva.lifecycle_state = att.lifecycle_state,
        bva.boot_volume_id = att.boot_volume_id,
        bva.instance_id = att.instance_id,
        bva.lastupdated = $oci_update_tag
        WITH bva, att
        MATCH (inode:OCIInstance{id: att.instance_id})
        MERGE (inode)-[r:OCI_BOOT_VOLUME_ATTACHMENT]->(bva)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = []
    for attachment in boot_volume_attachments:
        boot_volume_id = attachment.get("boot-volume-id", "")
        instance_id = attachment.get("instance-id", "")
        # OCI API returns instance OCID as the attachment's "id", so we use a
        # composite key to avoid colliding with OCIInstance nodes.
        bva_id = f"{instance_id}::{boot_volume_id}" if boot_volume_id else attachment.get("id")
        logger.debug(
            "Boot volume attachment id=%s, instance-id=%s, boot-volume-id=%s, using bva_id=%s",
            attachment.get("id"), instance_id, boot_volume_id, bva_id,
        )
        rows.append({
            "bva_id": bva_id,
            "ocid": attachment.get("id"),
            "display_name": attachment.get("display-name"),
            "compartment_id": attachment.get("compartment-id"),
            "availability_domain": attachment.get("availability-domain"),
            "lifecycle_state": attachment.get("lifecycle-state"),
            "boot_volume_id": boot_volume_id,
            "instance_id": instance_id,
            "time_created": str(attachment.get("time-created", "")),
        })
    load_graph_data(
        neo4j_session, ingest_boot_volume_attachment, rows,
        oci_update_tag=oci_update_tag,
    )


def get_volume_attachment_list_data(
    compute: oci.core.compute_client.ComputeClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all volume attachments in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/VolumeAttachment/ListVolumeAttachments
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            compute.list_volume_attachments, compartment_id=compartment_id,
        )
        return {'VolumeAttachments': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve volume attachments for compartment '%s': %s", compartment_id, e.message,
        )
        return {'VolumeAttachments': []}


def load_volume_attachments(
    neo4j_session: neo4j.Session,
    volume_attachments: List[Dict[str, Any]],
    tenancy_id: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Volume Attachment data into Neo4j and link to instances.
    """
    ingest_volume_attachment = """
    UNWIND $DictList AS att
        MERGE (va:OCIVolumeAttachment{id: att.ocid})
        ON CREATE SET va.firstseen = timestamp(),
        va.createdate = att.time_created
        SET va.ocid = att.ocid,
        va.display_name = att.display_name,
        va.compartment_id = att.compartment_id,
        va.availability_domain = att.availability_domain,
        va.lifecycle_state = att.lifecycle_state,
        va.volume_id = att.volume_id,
        va.attachment_type = att.attachment_type,
        va.is_read_only = att.is_read_only,
        va.lastupdated = $oci_update_tag
        WITH va, att
        MATCH (inode:OCIInstance{id: att.instance_id})
        MERGE (inode)-[r:OCI_VOLUME_ATTACHMENT]->(va)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": attachment.get("id"),
            "display_name": attachment.get("display-name"),
            "compartment_id": attachment.get("compartment-id"),
            "availability_domain": attachment.get("availability-domain"),
            "lifecycle_state": attachment.get("lifecycle-state"),
            "volume_id": attachment.get("volume-id"),
            "attachment_type": attachment.get("attachment-type"),
            "is_read_only": attachment.get("is-read-only"),
            "instance_id": attachment.get("instance-id"),
            "time_created": str(attachment.get("time-created", "")),
        }
        for attachment in volume_attachments
    ]
    load_graph_data(
        neo4j_session, ingest_volume_attachment, rows,
        oci_update_tag=oci_update_tag,
    )


def get_availability_domains(
    identity: oci.identity.identity_client.IdentityClient,
    compartment_id: str,
) -> List[str]:
    """
    Get the names of all availability domains in a compartment. Block/boot volume
    listing is scoped per availability domain.
    See https://docs.oracle.com/en-us/iaas/api/#/en/identity/latest/AvailabilityDomain/ListAvailabilityDomains
    """
    try:
        response = identity.list_availability_domains(compartment_id=compartment_id)
        return [ad.name for ad in response.data]
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve availability domains for compartment '%s': %s", compartment_id, e.message,
        )
        return []


def get_boot_volume_list_data(
    blockstorage: oci.core.blockstorage_client.BlockstorageClient,
    availability_domain: str,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all boot volumes in a compartment for a given availability domain.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/BootVolume/ListBootVolumes
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            blockstorage.list_boot_volumes,
            availability_domain=availability_domain,
            compartment_id=compartment_id,
        )
        return {'BootVolumes': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve boot volumes for compartment '%s', AD '%s': %s",
            compartment_id, availability_domain, e.message,
        )
        return {'BootVolumes': []}


def has_backup_policy_assigned(
    blockstorage: oci.core.blockstorage_client.BlockstorageClient,
    volume_id: str,
) -> bool:
    """
    Return True if the given volume (boot or block) has a backup policy assigned.
    Uses BlockstorageClient.get_volume_backup_policy_asset_assignment (asset_id = volume OCID).
    """
    if not volume_id:
        return False
    try:
        response = blockstorage.get_volume_backup_policy_asset_assignment(asset_id=volume_id)
        return bool(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve backup policy assignment for volume '%s': %s", volume_id, e.message,
        )
        return False


def load_boot_volumes(
    neo4j_session: neo4j.Session,
    boot_volumes: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Boot Volume data into Neo4j, link to its compartment, and link to the
    owning instance via its boot volume attachment.
    """
    ingest_boot_volume = """
    UNWIND $DictList AS vol
        MERGE (bv:OCIBootVolume{id: vol.ocid})
        ON CREATE SET bv.firstseen = timestamp(),
        bv.createdate = vol.time_created
        SET bv.ocid = vol.ocid,
        bv.display_name = vol.display_name,
        bv.compartment_id = vol.compartment_id,
        bv.resource_type = 'oci-storage-blockstorage-bootvolume',
        bv.availability_domain = vol.availability_domain,
        bv.lifecycle_state = vol.lifecycle_state,
        bv.size_in_gbs = vol.size_in_gbs,
        bv.kms_key_id = vol.kms_key_id,
        bv.is_hydrated = vol.is_hydrated,
        bv.vpus_per_gb = vol.vpus_per_gb,
        bv.image_id = vol.image_id,
        bv.has_backup_policy = vol.has_backup_policy,
        bv.region = $REGION,
        bv.lastupdated = $oci_update_tag
        WITH bv, vol
        MATCH (cc:OCICompartment{id: vol.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(bv)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
        WITH bv, vol
        OPTIONAL MATCH (inode:OCIInstance)-[:OCI_BOOT_VOLUME_ATTACHMENT]->(:OCIBootVolumeAttachment{boot_volume_id: vol.ocid})
        FOREACH (_ IN CASE WHEN inode IS NULL THEN [] ELSE [1] END |
            MERGE (inode)-[ri:OCI_BOOT_VOLUME]->(bv)
            ON CREATE SET ri.firstseen = timestamp()
            SET ri.lastupdated = $oci_update_tag
        )
    """

    rows = [
        {
            "ocid": volume.get("id"),
            "display_name": volume.get("display-name"),
            "compartment_id": volume.get("compartment-id", compartment_id),
            "availability_domain": volume.get("availability-domain", ""),
            "lifecycle_state": volume.get("lifecycle-state"),
            "size_in_gbs": volume.get("size-in-gbs"),
            "kms_key_id": volume.get("kms-key-id", ""),
            "is_hydrated": volume.get("is-hydrated"),
            "vpus_per_gb": volume.get("vpus-per-gb"),
            "image_id": volume.get("image-id", ""),
            "has_backup_policy": volume.get("_has_backup_policy", False),
            "time_created": str(volume.get("time-created", "")),
        }
        for volume in boot_volumes
    ]
    load_graph_data(
        neo4j_session, ingest_boot_volume, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def get_block_volume_list_data(
    blockstorage: oci.core.blockstorage_client.BlockstorageClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all block volumes in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/Volume/ListVolumes
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            blockstorage.list_volumes, compartment_id=compartment_id,
        )
        return {'Volumes': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve block volumes for compartment '%s': %s", compartment_id, e.message,
        )
        return {'Volumes': []}


def load_block_volumes(
    neo4j_session: neo4j.Session,
    block_volumes: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Block Volume data into Neo4j, link to its compartment, and create an
    ATTACHED_TO relationship to the instance via its volume attachment.
    """
    ingest_block_volume = """
    UNWIND $DictList AS vol
        MERGE (bv:OCIBlockVolume{id: vol.ocid})
        ON CREATE SET bv.firstseen = timestamp(),
        bv.createdate = vol.time_created
        SET bv.ocid = vol.ocid,
        bv.display_name = vol.display_name,
        bv.compartment_id = vol.compartment_id,
        bv.resource_type = 'oci-storage-blockstorage-volume',
        bv.availability_domain = vol.availability_domain,
        bv.lifecycle_state = vol.lifecycle_state,
        bv.size_in_gbs = vol.size_in_gbs,
        bv.kms_key_id = vol.kms_key_id,
        bv.is_hydrated = vol.is_hydrated,
        bv.vpus_per_gb = vol.vpus_per_gb,
        bv.has_backup_policy = vol.has_backup_policy,
        bv.region = $REGION,
        bv.lastupdated = $oci_update_tag
        WITH bv, vol
        MATCH (cc:OCICompartment{id: vol.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(bv)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
        WITH bv, vol
        OPTIONAL MATCH (inode:OCIInstance)-[:OCI_VOLUME_ATTACHMENT]->(:OCIVolumeAttachment{volume_id: vol.ocid})
        FOREACH (_ IN CASE WHEN inode IS NULL THEN [] ELSE [1] END |
            MERGE (bv)-[ri:ATTACHED_TO]->(inode)
            ON CREATE SET ri.firstseen = timestamp()
            SET ri.lastupdated = $oci_update_tag
        )
    """

    rows = [
        {
            "ocid": volume.get("id"),
            "display_name": volume.get("display-name"),
            "compartment_id": volume.get("compartment-id", compartment_id),
            "availability_domain": volume.get("availability-domain", ""),
            "lifecycle_state": volume.get("lifecycle-state"),
            "size_in_gbs": volume.get("size-in-gbs"),
            "kms_key_id": volume.get("kms-key-id", ""),
            "is_hydrated": volume.get("is-hydrated"),
            "vpus_per_gb": volume.get("vpus-per-gb"),
            "has_backup_policy": volume.get("_has_backup_policy", False),
            "time_created": str(volume.get("time-created", "")),
        }
        for volume in block_volumes
    ]
    load_graph_data(
        neo4j_session, ingest_block_volume, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_boot_volume_attachments(
    neo4j_session: neo4j.Session,
    compute: oci.core.compute_client.ComputeClient,
    availability_domains: List[str],
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all boot volume attachments across compartments and availability domains.
    """
    logger.debug("Syncing OCI boot volume attachments for tenancy '%s'.", tenancy_id)
    for compartment in compartments:
        for availability_domain in availability_domains:
            data = get_boot_volume_attachment_list_data(compute, availability_domain, compartment["ocid"])
            if data["BootVolumeAttachments"]:
                load_boot_volume_attachments(
                    neo4j_session, data["BootVolumeAttachments"], tenancy_id, oci_update_tag,
                )


def sync_boot_volumes(
    neo4j_session: neo4j.Session,
    blockstorage: oci.core.blockstorage_client.BlockstorageClient,
    availability_domains: List[str],
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all boot volumes across compartments and availability domains, enriching each
    with whether a backup policy is assigned.
    """
    logger.debug("Syncing OCI boot volumes for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        for availability_domain in availability_domains:
            data = get_boot_volume_list_data(blockstorage, availability_domain, compartment["ocid"])
            for volume in data["BootVolumes"]:
                volume["_has_backup_policy"] = has_backup_policy_assigned(blockstorage, volume.get("id"))
            if data["BootVolumes"]:
                load_boot_volumes(
                    neo4j_session, data["BootVolumes"], tenancy_id, compartment["ocid"], region, oci_update_tag,
                )


def sync_block_volumes(
    neo4j_session: neo4j.Session,
    blockstorage: oci.core.blockstorage_client.BlockstorageClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all block volumes across compartments, enriching each with whether a backup
    policy is assigned.
    """
    logger.debug("Syncing OCI block volumes for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_block_volume_list_data(blockstorage, compartment["ocid"])
        for volume in data["Volumes"]:
            volume["_has_backup_policy"] = has_backup_policy_assigned(blockstorage, volume.get("id"))
        if data["Volumes"]:
            load_block_volumes(
                neo4j_session, data["Volumes"], tenancy_id, compartment["ocid"], region, oci_update_tag,
            )


def sync_instances(
    neo4j_session: neo4j.Session,
    compute: oci.core.compute_client.ComputeClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all compute instances across all compartments in the tenancy.
    """
    tic = time.perf_counter()
    logger.debug("Syncing OCI compute instances for tenancy '%s', region '%s'.", tenancy_id, region)
    total = 0
    for compartment in compartments:
        data = get_instance_list_data(compute, compartment["ocid"])
        if data["Instances"]:
            total += len(data["Instances"])
            load_instances(neo4j_session, data["Instances"], tenancy_id, compartment["ocid"], region, oci_update_tag)
    logger.info(f"Time to process OCI compute instances for tenancy '{tenancy_id}' region '{region}' ({total} instances): {time.perf_counter() - tic:0.4f} seconds")


def sync_vnic_attachments(
    neo4j_session: neo4j.Session,
    compute: oci.core.compute_client.ComputeClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all VNIC attachments across all compartments in the tenancy.
    """
    tic = time.perf_counter()
    logger.debug("Syncing OCI VNIC attachments for tenancy '%s'.", tenancy_id)
    total = 0
    for compartment in compartments:
        data = get_vnic_attachment_list_data(compute, compartment["ocid"])
        if data["VnicAttachments"]:
            total += len(data["VnicAttachments"])
            load_vnic_attachments(neo4j_session, data["VnicAttachments"], tenancy_id, oci_update_tag)
    logger.info(f"Time to process OCI VNIC attachments for tenancy '{tenancy_id}' ({total} attachments): {time.perf_counter() - tic:0.4f} seconds")


def sync_images(
    neo4j_session: neo4j.Session,
    compute: oci.core.compute_client.ComputeClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all images across all compartments in the tenancy.
    """
    tic = time.perf_counter()
    logger.debug("Syncing OCI images for tenancy '%s'.", tenancy_id)
    total = 0
    for compartment in compartments:
        data = get_image_list_data(compute, compartment["ocid"])
        if data["Images"]:
            total += len(data["Images"])
            load_images(neo4j_session, data["Images"], tenancy_id, compartment["ocid"], oci_update_tag)
    logger.info(f"Time to process OCI images for tenancy '{tenancy_id}' ({total} images): {time.perf_counter() - tic:0.4f} seconds")


def sync_volume_attachments(
    neo4j_session: neo4j.Session,
    compute: oci.core.compute_client.ComputeClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all volume attachments across all compartments in the tenancy.
    """
    tic = time.perf_counter()
    logger.debug("Syncing OCI volume attachments for tenancy '%s'.", tenancy_id)
    total = 0
    for compartment in compartments:
        data = get_volume_attachment_list_data(compute, compartment["ocid"])
        if data["VolumeAttachments"]:
            total += len(data["VolumeAttachments"])
            load_volume_attachments(neo4j_session, data["VolumeAttachments"], tenancy_id, oci_update_tag)
    logger.info(f"Time to process OCI volume attachments for tenancy '{tenancy_id}' ({total} attachments): {time.perf_counter() - tic:0.4f} seconds")


def sync(
    neo4j_session: neo4j.Session,
    compute: oci.core.compute_client.ComputeClient,
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
    regions: List[str] = None,
) -> None:
    """
    Sync OCI Compute resources for the compartment specified in common_job_parameters.
    """
    tic = time.perf_counter()
    compartment_ocid = common_job_parameters.get("OCI_COMPARTMENT_ID", tenancy_id)
    logger.info("Syncing OCI Compute for compartment '%s'.", compartment_ocid)

    # Use only the target compartment for resource listing
    compartments = [{"ocid": compartment_ocid, "name": "target", "compartmentid": tenancy_id}]

    # If no regions provided, use the compute client's current region
    if not regions:
        regions = [compute.base_client.region or ""]

    # Block storage (boot/block volumes) and identity (availability domains) live on
    # separate clients. Reuse the compute client's config/signer so we authenticate
    # identically.
    blockstorage = oci.core.BlockstorageClient(
        config=compute.base_client.config,
        signer=getattr(compute.base_client, "signer", None),
    )
    identity = oci.identity.IdentityClient(
        config=compute.base_client.config,
        signer=getattr(compute.base_client, "signer", None),
    )

    for region in regions:
        logger.info("Syncing OCI Compute in region '%s' for compartment '%s'.", region, compartment_ocid)
        compute.base_client.set_region(region)
        blockstorage.base_client.set_region(region)
        identity.base_client.set_region(region)

        # Availability domains are needed to scope boot volume / boot volume attachment listing.
        availability_domains: List[str] = []
        for compartment in compartments:
            availability_domains.extend(get_availability_domains(identity, compartment["ocid"]))
        # De-duplicate while preserving order.
        availability_domains = list(dict.fromkeys(availability_domains))

        # Sync instances
        sync_instances(neo4j_session, compute, compartments, tenancy_id, region, oci_update_tag, common_job_parameters)

        # Sync VNIC attachments (links instances to network interfaces)
        sync_vnic_attachments(neo4j_session, compute, compartments, tenancy_id, oci_update_tag, common_job_parameters)

        # Sync images
        sync_images(neo4j_session, compute, compartments, tenancy_id, oci_update_tag, common_job_parameters)

        # Sync boot volume attachments (links instances to boot volumes)
        sync_boot_volume_attachments(
            neo4j_session, compute, availability_domains, compartments, tenancy_id,
            oci_update_tag, common_job_parameters,
        )

        # Sync volume attachments (block volumes attached to instances)
        sync_volume_attachments(neo4j_session, compute, compartments, tenancy_id, oci_update_tag, common_job_parameters)

        # Sync boot volumes (with kms_key_id + has_backup_policy; links to instance)
        sync_boot_volumes(
            neo4j_session, blockstorage, availability_domains, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

        # Sync block volumes (with kms_key_id + has_backup_policy; ATTACHED_TO instance)
        sync_block_volumes(
            neo4j_session, blockstorage, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

    # Cleanup stale nodes
    run_cleanup_job('oci_import_compute_instances_cleanup.json', neo4j_session, common_job_parameters)
    toc = time.perf_counter()
    logger.info(f"Time to process OCI Compute for tenancy '{tenancy_id}': {toc - tic:0.4f} seconds")
