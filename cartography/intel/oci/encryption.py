# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI Key Management Service (KMS) API-centric functions
# https://docs.oracle.com/en-us/iaas/Content/KeyManagement/Concepts/keyoverview.htm
import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j
import oci.key_management

from . import utils
from cartography.client.core.tx import load_graph_data
from cartography.util import run_cleanup_job

logger = logging.getLogger(__name__)


# ============================================================
# KMS Vaults
# ============================================================

def get_vault_list_data(
    kms_vault: oci.key_management.KmsVaultClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all KMS vaults in a compartment.
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            kms_vault.list_vaults, compartment_id=compartment_id,
        )
        return {'Vaults': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve KMS vaults for compartment '%s': %s",
            compartment_id, e.message,
        )
        return {'Vaults': []}


def load_vaults(
    neo4j_session: neo4j.Session,
    vaults: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI KMS Vault data into Neo4j.
    """
    ingest_vault = """
    UNWIND $DictList AS vault
        MERGE (v:OCIKmsVault{id: vault.ocid})
        ON CREATE SET v.firstseen = timestamp(),
        v.createdate = vault.time_created
        SET v.ocid = vault.ocid,
        v.display_name = vault.display_name,
        v.compartment_id = vault.compartment_id,
        v.resource_type = 'oci-kms-vault',
        v.vault_type = vault.vault_type,
        v.lifecycle_state = vault.lifecycle_state,
        v.crypto_endpoint = vault.crypto_endpoint,
        v.management_endpoint = vault.management_endpoint,
        v.region = $REGION,
        v.lastupdated = $oci_update_tag
        WITH v, vault
        MATCH (cc:OCICompartment{id: vault.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(v)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": vault.get("id"),
            "display_name": vault.get("display-name"),
            "compartment_id": vault.get("compartment-id", compartment_id),
            "vault_type": vault.get("vault-type", ""),
            "lifecycle_state": vault.get("lifecycle-state"),
            "crypto_endpoint": vault.get("crypto-endpoint", ""),
            "management_endpoint": vault.get("management-endpoint", ""),
            "time_created": str(vault.get("time-created", "")),
        }
        for vault in vaults
    ]
    load_graph_data(
        neo4j_session, ingest_vault, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_vaults(
    neo4j_session: neo4j.Session,
    kms_vault: oci.key_management.KmsVaultClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all KMS vaults across compartments.
    """
    logger.debug("Syncing OCI KMS vaults for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_vault_list_data(kms_vault, compartment["ocid"])
        if data["Vaults"]:
            load_vaults(
                neo4j_session, data["Vaults"], tenancy_id,
                compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# KMS Keys
# ============================================================

def get_key_list_data(
    management_endpoint: str,
    credentials: Dict[str, Any],
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all keys managed by a vault (via its management endpoint).
    Each vault exposes its own management endpoint for key operations.
    """
    try:
        kms_management = oci.key_management.KmsManagementClient(
            credentials, service_endpoint=management_endpoint,
        )
        response = oci.pagination.list_call_get_all_results(
            kms_management.list_keys, compartment_id=compartment_id,
        )
        return {'Keys': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve KMS keys from endpoint '%s': %s",
            management_endpoint, e.message,
        )
        return {'Keys': []}


def get_key_details(
    management_endpoint: str,
    credentials: Dict[str, Any],
    key_id: str,
) -> Dict[str, Any]:
    """
    Get full details of a single key (includes key versions, rotation info).
    """
    try:
        kms_management = oci.key_management.KmsManagementClient(
            credentials, service_endpoint=management_endpoint,
        )
        response = kms_management.get_key(key_id=key_id)
        return utils.oci_single_object_to_json(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve KMS key '%s': %s", key_id, e.message,
        )
        return {}


def load_keys(
    neo4j_session: neo4j.Session,
    keys: List[Dict[str, Any]],
    vault_id: str,
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI KMS Key data into Neo4j and link to vault.
    """
    ingest_key = """
    UNWIND $DictList AS key
        MERGE (k:OCIKmsKey{id: key.ocid})
        ON CREATE SET k.firstseen = timestamp(),
        k.createdate = key.time_created
        SET k.ocid = key.ocid,
        k.display_name = key.display_name,
        k.compartment_id = key.compartment_id,
        k.resource_type = 'oci-kms-key',
        k.vault_id = $VAULT_ID,
        k.algorithm = key.algorithm,
        k.protection_mode = key.protection_mode,
        k.lifecycle_state = key.lifecycle_state,
        k.current_key_version = key.current_key_version,
        k.region = $REGION,
        k.lastupdated = $oci_update_tag
        WITH k
        MATCH (v:OCIKmsVault{id: $VAULT_ID})
        MERGE (v)-[r:OCI_KMS_KEY]->(k)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": key.get("id"),
            "display_name": key.get("display-name"),
            "compartment_id": key.get("compartment-id", compartment_id),
            "algorithm": key.get("algorithm", ""),
            "protection_mode": key.get("protection-mode", ""),
            "lifecycle_state": key.get("lifecycle-state"),
            "current_key_version": key.get("current-key-version", ""),
            "time_created": str(key.get("time-created", "")),
        }
        for key in keys
    ]
    load_graph_data(
        neo4j_session, ingest_key, rows,
        VAULT_ID=vault_id, REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_keys(
    neo4j_session: neo4j.Session,
    kms_vault: oci.key_management.KmsVaultClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all KMS keys by iterating vaults already in Neo4j and fetching keys
    from each vault's management endpoint.
    """
    logger.debug("Syncing OCI KMS keys for tenancy '%s', region '%s'.", tenancy_id, region)
    credentials = kms_vault.base_client.config

    for compartment in compartments:
        query = (
            "MATCH (:OCICompartment{id: $COMPARTMENT_ID})"
            "-[:RESOURCE]->(v:OCIKmsVault) "
            "WHERE v.region = $REGION AND v.lifecycle_state = 'ACTIVE' "
            "RETURN v.ocid as ocid, v.management_endpoint as endpoint"
        )
        vaults = neo4j_session.run(
            query, COMPARTMENT_ID=compartment["ocid"], REGION=region,
        )
        for vault in vaults:
            endpoint = vault["endpoint"]
            if not endpoint:
                continue
            data = get_key_list_data(endpoint, credentials, compartment["ocid"])
            if data["Keys"]:
                load_keys(
                    neo4j_session, data["Keys"], vault["ocid"],
                    tenancy_id, compartment["ocid"], region, oci_update_tag,
                )


# ============================================================
# Top-level sync function
# ============================================================

def sync(
    neo4j_session: neo4j.Session,
    encryption: oci.key_management.KmsVaultClient,
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
    regions: List[str] = None,
) -> None:
    """
    Sync OCI Encryption (KMS) resources: Vaults and Keys.
    """
    compartment_ocid = common_job_parameters.get("OCI_COMPARTMENT_ID", tenancy_id)
    logger.info("Syncing OCI Encryption for compartment '%s'.", compartment_ocid)

    compartments = [
        {"ocid": compartment_ocid, "name": "target", "compartmentid": tenancy_id},
    ]

    if not regions:
        regions = [encryption.base_client.region or ""]

    for region in regions:
        logger.info(
            "Syncing OCI Encryption in region '%s' for compartment '%s'.",
            region, compartment_ocid,
        )
        encryption.base_client.set_region(region)

        # Sync vaults first
        sync_vaults(
            neo4j_session, encryption, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

        # Sync keys (depends on vaults being in Neo4j)
        sync_keys(
            neo4j_session, encryption, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

    # Cleanup stale encryption nodes
    run_cleanup_job(
        'oci_import_encryption_cleanup.json', neo4j_session, common_job_parameters,
    )
