# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI Database service: Autonomous Database + Base Database System.
# https://docs.oracle.com/en-us/iaas/Content/Database/Concepts/databaseoverview.htm
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import neo4j
import oci

from . import utils
from cartography.util import run_cleanup_job

logger = logging.getLogger(__name__)


# Lifecycle states we consider "live" infrastructure worth ingesting.
# - AVAILABLE / UPDATING / PROVISIONING: real, billable, security-relevant.
# - STOPPED (Autonomous DB only): paid resource still configured with NSGs,
#   whitelisted IPs, and KMS keys — keep it visible to posture checks.
# - AVAILABLE_NEEDS_ATTENTION (Autonomous DB only): functional, just flagging
#   operator action — same security surface as AVAILABLE.
#
# Filtering server-side avoids fetching tombstones (TERMINATED / TERMINATING /
# FAILED / RESTORE_FAILED / UNAVAILABLE / INACCESSIBLE / MIGRATED).
ACTIVE_DB_SYSTEM_STATES: List[str] = ["AVAILABLE", "UPDATING", "PROVISIONING"]
ACTIVE_DB_HOME_STATES: List[str] = ["AVAILABLE", "UPDATING", "PROVISIONING"]
ACTIVE_DB_NODE_STATES: List[str] = ["AVAILABLE", "UPDATING", "PROVISIONING"]
ACTIVE_AUTONOMOUS_DB_STATES: List[str] = [
    "AVAILABLE", "UPDATING", "PROVISIONING",
    "STOPPED", "AVAILABLE_NEEDS_ATTENTION",
]


def _list_with_lifecycle_filter(
    list_fn: Any,
    lifecycle_states: List[str],
    **kwargs: Any,
) -> List[Any]:
    """
    The OCI Database APIs accept ``lifecycle_state`` as a *single* string rather
    than a list (unlike Container Engine). To filter server-side we have to
    issue one paginated call per state and concatenate the results. Returns the
    raw OCI SDK objects so callers can pass them to ``utils.oci_object_to_json``.
    """
    aggregated: List[Any] = []
    for state in lifecycle_states:
        try:
            response = oci.pagination.list_call_get_all_results(
                list_fn, lifecycle_state=state, **kwargs,
            )
            if response.data:
                aggregated.extend(response.data)
        except oci.exceptions.ServiceError as e:
            logger.warning(
                "list call failed for lifecycle_state '%s' (kwargs=%s): %s",
                state, kwargs, e.message,
            )
    return aggregated


# ---------------------------------------------------------------------------
# Autonomous Database
# ---------------------------------------------------------------------------

def get_autonomous_database_list_data(
    database_client: oci.database.DatabaseClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    List Autonomous Databases in a compartment, server-side filtered to live
    states. See:
    https://docs.oracle.com/en-us/iaas/api/#/en/database/latest/AutonomousDatabase/ListAutonomousDatabases
    """
    try:
        raw = _list_with_lifecycle_filter(
            database_client.list_autonomous_databases,
            ACTIVE_AUTONOMOUS_DB_STATES,
            compartment_id=compartment_id,
        )
        return {'AutonomousDatabases': utils.oci_object_to_json(raw)}
    except Exception as e:
        logger.warning(
            "Could not retrieve Autonomous Databases for compartment '%s': %s",
            compartment_id, e,
        )
        return {'AutonomousDatabases': []}


def transform_autonomous_databases(
    autonomous_databases: List[Dict[str, Any]],
    region: str,
) -> List[Dict[str, Any]]:
    """
    Shape Autonomous Database payloads to the keys ``load_autonomous_databases``
    expects. Surfaces every property our security posture checks care about:
    public-vs-private endpoint, NSG attachments, whitelisted IPs, mTLS
    enforcement, KMS encryption, Data Safe status, ORDS/APEX exposure.
    """
    transformed: List[Dict[str, Any]] = []
    for adb in autonomous_databases:
        if not adb.get("id"):
            continue

        # Defensive guard mirrors the OKE pattern.
        lifecycle_state = adb.get("lifecycle-state")
        if lifecycle_state not in ACTIVE_AUTONOMOUS_DB_STATES:
            logger.debug(
                "Skipping Autonomous DB '%s' in lifecycle_state '%s'.",
                adb.get("id"), lifecycle_state,
            )
            continue

        connection_strings = adb.get("connection-strings") or {}
        connection_urls = adb.get("connection-urls") or {}
        # whitelisted-ips is the network ACL on Autonomous Databases.
        # An empty list means "no public IP allowed". A non-empty list
        # is itself a signal worth exposing as a single boolean.
        whitelisted_ips = adb.get("whitelisted-ips") or []
        nsg_ids = adb.get("nsg-ids") or []

        transformed.append({
            "ocid": adb.get("id"),
            "id": adb.get("id"),
            "display_name": adb.get("display-name"),
            "compartment_id": adb.get("compartment-id"),
            "db_name": adb.get("db-name"),
            "db_workload": adb.get("db-workload"),
            "db_version": adb.get("db-version"),
            "lifecycle_state": lifecycle_state,
            "lifecycle_details": adb.get("lifecycle-details"),
            "license_model": adb.get("license-model"),
            "infrastructure_type": adb.get("infrastructure-type"),
            "is_dedicated": bool(adb.get("is-dedicated", False)),
            "is_free_tier": bool(adb.get("is-free-tier", False)),
            "is_preview": bool(adb.get("is-preview", False)),
            "cpu_core_count": adb.get("cpu-core-count"),
            "ocpu_count": adb.get("ocpu-count"),
            "compute_count": adb.get("compute-count"),
            "compute_model": adb.get("compute-model"),
            "data_storage_size_in_tbs": adb.get("data-storage-size-in-tbs"),
            "data_storage_size_in_gbs": adb.get("data-storage-size-in-gbs"),
            "is_auto_scaling_enabled": bool(adb.get("is-auto-scaling-enabled", False)),
            "is_auto_scaling_for_storage_enabled": bool(
                adb.get("is-auto-scaling-for-storage-enabled", False),
            ),
            # Network exposure
            "subnet_id": adb.get("subnet-id"),
            "private_endpoint": adb.get("private-endpoint"),
            "private_endpoint_ip": adb.get("private-endpoint-ip"),
            "private_endpoint_label": adb.get("private-endpoint-label"),
            "nsg_ids": nsg_ids,
            "whitelisted_ips": whitelisted_ips,
            "are_primary_whitelisted_ips_used": adb.get(
                "are-primary-whitelisted-ips-used",
            ),
            # is_public is a derived signal: a public ADB has no subnet_id and
            # is reachable over the internet (subject to the whitelist).
            "is_public": adb.get("subnet-id") is None,
            # Access control
            "is_mtls_connection_required": bool(
                adb.get("is-mtls-connection-required", True),
            ),
            "is_access_control_enabled": bool(
                adb.get("is-access-control-enabled", False),
            ),
            # Encryption
            "kms_key_id": adb.get("kms-key-id"),
            "vault_id": adb.get("vault-id"),
            "kms_key_lifecycle_details": adb.get("kms-key-lifecycle-details"),
            "is_encrypted_with_cmk": bool(adb.get("kms-key-id")),
            # Connection endpoints (security-relevant: ORDS / APEX surfaces)
            "service_console_url": connection_urls.get("sql-dev-web-url")
            or connection_urls.get("apex-url"),
            "apex_url": connection_urls.get("apex-url"),
            "graph_studio_url": connection_urls.get("graph-studio-url"),
            "machine_learning_user_management_url": connection_urls.get(
                "machine-learning-user-management-url",
            ),
            "ords_url": connection_urls.get("ords-url"),
            "connection_profile_count": len(
                connection_strings.get("profiles") or [],
            ),
            # Governance / posture
            "data_safe_status": adb.get("data-safe-status"),
            "database_management_status": adb.get("database-management-status"),
            "operations_insights_status": adb.get("operations-insights-status"),
            "open_mode": adb.get("open-mode"),
            "permission_level": adb.get("permission-level"),
            "role": adb.get("role"),
            "available_upgrade_versions": adb.get("available-upgrade-versions") or [],
            "time_created": str(adb.get("time-created", "")),
            "region": region,
        })
    return transformed


def load_autonomous_databases(
    neo4j_session: neo4j.Session,
    autonomous_databases: List[Dict[str, Any]],
    compartment_id: str,
    oci_update_tag: int,
) -> None:
    """
    Batch-ingest OCIAutonomousDatabase nodes, attach to compartment, and link
    to KMS key / subnet / NSGs via MATCH-only edges (safe no-op if those
    upstream nodes have not been synced yet).
    """
    ingest_adb = """
    UNWIND $items AS adb
        MERGE (a:OCIAutonomousDatabase{id: adb.id})
        ON CREATE SET a.firstseen = timestamp(),
                      a.createdate = adb.time_created
        SET a.ocid = adb.ocid,
            a.display_name = adb.display_name,
            a.compartment_id = adb.compartment_id,
            a.db_name = adb.db_name,
            a.db_workload = adb.db_workload,
            a.db_version = adb.db_version,
            a.lifecycle_state = adb.lifecycle_state,
            a.lifecycle_details = adb.lifecycle_details,
            a.license_model = adb.license_model,
            a.infrastructure_type = adb.infrastructure_type,
            a.is_dedicated = adb.is_dedicated,
            a.is_free_tier = adb.is_free_tier,
            a.is_preview = adb.is_preview,
            a.cpu_core_count = adb.cpu_core_count,
            a.ocpu_count = adb.ocpu_count,
            a.compute_count = adb.compute_count,
            a.compute_model = adb.compute_model,
            a.data_storage_size_in_tbs = adb.data_storage_size_in_tbs,
            a.data_storage_size_in_gbs = adb.data_storage_size_in_gbs,
            a.is_auto_scaling_enabled = adb.is_auto_scaling_enabled,
            a.is_auto_scaling_for_storage_enabled = adb.is_auto_scaling_for_storage_enabled,
            a.subnet_id = adb.subnet_id,
            a.private_endpoint = adb.private_endpoint,
            a.private_endpoint_ip = adb.private_endpoint_ip,
            a.private_endpoint_label = adb.private_endpoint_label,
            a.nsg_ids = adb.nsg_ids,
            a.whitelisted_ips = adb.whitelisted_ips,
            a.are_primary_whitelisted_ips_used = adb.are_primary_whitelisted_ips_used,
            a.is_public = adb.is_public,
            a.is_mtls_connection_required = adb.is_mtls_connection_required,
            a.is_access_control_enabled = adb.is_access_control_enabled,
            a.kms_key_id = adb.kms_key_id,
            a.vault_id = adb.vault_id,
            a.kms_key_lifecycle_details = adb.kms_key_lifecycle_details,
            a.is_encrypted_with_cmk = adb.is_encrypted_with_cmk,
            a.service_console_url = adb.service_console_url,
            a.apex_url = adb.apex_url,
            a.graph_studio_url = adb.graph_studio_url,
            a.machine_learning_user_management_url = adb.machine_learning_user_management_url,
            a.ords_url = adb.ords_url,
            a.connection_profile_count = adb.connection_profile_count,
            a.data_safe_status = adb.data_safe_status,
            a.database_management_status = adb.database_management_status,
            a.operations_insights_status = adb.operations_insights_status,
            a.open_mode = adb.open_mode,
            a.permission_level = adb.permission_level,
            a.role = adb.role,
            a.available_upgrade_versions = adb.available_upgrade_versions,
            a.region = adb.region,
            a.lastupdated = $oci_update_tag
        WITH a
        MATCH (cc:OCICompartment{id: $COMPARTMENT_ID})
        MERGE (cc)-[r:RESOURCE]->(a)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    neo4j_session.run(
        ingest_adb,
        items=autonomous_databases,
        COMPARTMENT_ID=compartment_id,
        oci_update_tag=oci_update_tag,
    )

    _link_subnet_and_nsg(
        neo4j_session,
        label="OCIAutonomousDatabase",
        items=autonomous_databases,
        oci_update_tag=oci_update_tag,
    )
    _link_kms_key(
        neo4j_session,
        label="OCIAutonomousDatabase",
        items=autonomous_databases,
        oci_update_tag=oci_update_tag,
    )


def sync_autonomous_databases(
    neo4j_session: neo4j.Session,
    database_client: oci.database.DatabaseClient,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    logger.debug(
        "Syncing OCI Autonomous Databases for compartment '%s', region '%s'.",
        compartment_id, region,
    )
    raw = get_autonomous_database_list_data(database_client, compartment_id)["AutonomousDatabases"]
    items = transform_autonomous_databases(raw, region)
    if items:
        load_autonomous_databases(neo4j_session, items, compartment_id, oci_update_tag)


# ---------------------------------------------------------------------------
# DB Systems (Base Database)
# ---------------------------------------------------------------------------

def get_db_system_list_data(
    database_client: oci.database.DatabaseClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    List Base Database Systems in a compartment, server-side filtered.
    See https://docs.oracle.com/en-us/iaas/api/#/en/database/latest/DbSystem/ListDbSystems
    """
    try:
        raw = _list_with_lifecycle_filter(
            database_client.list_db_systems,
            ACTIVE_DB_SYSTEM_STATES,
            compartment_id=compartment_id,
        )
        return {'DbSystems': utils.oci_object_to_json(raw)}
    except Exception as e:
        logger.warning(
            "Could not retrieve DB Systems for compartment '%s': %s",
            compartment_id, e,
        )
        return {'DbSystems': []}


def transform_db_systems(
    db_systems: List[Dict[str, Any]],
    region: str,
) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for sys in db_systems:
        if not sys.get("id"):
            continue
        lifecycle_state = sys.get("lifecycle-state")
        if lifecycle_state not in ACTIVE_DB_SYSTEM_STATES:
            logger.debug(
                "Skipping DB System '%s' in lifecycle_state '%s'.",
                sys.get("id"), lifecycle_state,
            )
            continue

        iorm = sys.get("iorm-config-cache") or {}
        maintenance = sys.get("maintenance-window") or {}
        ssh_keys = sys.get("ssh-public-keys") or []

        transformed.append({
            "ocid": sys.get("id"),
            "id": sys.get("id"),
            "display_name": sys.get("display-name"),
            "compartment_id": sys.get("compartment-id"),
            "availability_domain": sys.get("availability-domain"),
            "fault_domains": sys.get("fault-domains") or [],
            "shape": sys.get("shape"),
            "cpu_core_count": sys.get("cpu-core-count"),
            "node_count": sys.get("node-count"),
            "data_storage_size_in_gbs": sys.get("data-storage-size-in-gbs"),
            "reco_storage_size_in_gb": sys.get("reco-storage-size-in-gb"),
            "storage_volume_performance_mode": sys.get(
                "storage-volume-performance-mode",
            ),
            "database_edition": sys.get("database-edition"),
            "version": sys.get("version"),
            "license_model": sys.get("license-model"),
            "lifecycle_state": lifecycle_state,
            "lifecycle_details": sys.get("lifecycle-details"),
            "disk_redundancy": sys.get("disk-redundancy"),
            # Network exposure
            "subnet_id": sys.get("subnet-id"),
            "backup_subnet_id": sys.get("backup-subnet-id"),
            "nsg_ids": sys.get("nsg-ids") or [],
            "backup_network_nsg_ids": sys.get("backup-network-nsg-ids") or [],
            "scan_dns_name": sys.get("scan-dns-name"),
            "zone_id": sys.get("zone-id"),
            "scan_ip_ids": sys.get("scan-ip-ids") or [],
            "vip_ids": sys.get("vip-ids") or [],
            "private_ip": sys.get("private-ip"),
            "hostname": sys.get("hostname"),
            "domain": sys.get("domain"),
            "listener_port": sys.get("listener-port"),
            "cluster_name": sys.get("cluster-name"),
            "data_storage_percentage": sys.get("data-storage-percentage"),
            # Encryption / SSH
            "kms_key_id": sys.get("kms-key-id"),
            "is_encrypted_with_cmk": bool(sys.get("kms-key-id")),
            "ssh_public_key_count": len(ssh_keys),
            "has_ssh_public_keys": bool(ssh_keys),
            # Posture
            "data_safe_status": sys.get("data-safe-status"),
            "database_management_status": sys.get("database-management-status"),
            "iorm_lifecycle_state": iorm.get("lifecycle-state"),
            "maintenance_window_preference": maintenance.get("preference"),
            "time_created": str(sys.get("time-created", "")),
            "region": region,
        })
    return transformed


def load_db_systems(
    neo4j_session: neo4j.Session,
    db_systems: List[Dict[str, Any]],
    compartment_id: str,
    oci_update_tag: int,
) -> None:
    ingest_db_system = """
    UNWIND $items AS s
        MERGE (sys:OCIDbSystem{id: s.id})
        ON CREATE SET sys.firstseen = timestamp(),
                      sys.createdate = s.time_created
        SET sys.ocid = s.ocid,
            sys.display_name = s.display_name,
            sys.compartment_id = s.compartment_id,
            sys.availability_domain = s.availability_domain,
            sys.fault_domains = s.fault_domains,
            sys.shape = s.shape,
            sys.cpu_core_count = s.cpu_core_count,
            sys.node_count = s.node_count,
            sys.data_storage_size_in_gbs = s.data_storage_size_in_gbs,
            sys.reco_storage_size_in_gb = s.reco_storage_size_in_gb,
            sys.storage_volume_performance_mode = s.storage_volume_performance_mode,
            sys.database_edition = s.database_edition,
            sys.version = s.version,
            sys.license_model = s.license_model,
            sys.lifecycle_state = s.lifecycle_state,
            sys.lifecycle_details = s.lifecycle_details,
            sys.disk_redundancy = s.disk_redundancy,
            sys.subnet_id = s.subnet_id,
            sys.backup_subnet_id = s.backup_subnet_id,
            sys.nsg_ids = s.nsg_ids,
            sys.backup_network_nsg_ids = s.backup_network_nsg_ids,
            sys.scan_dns_name = s.scan_dns_name,
            sys.zone_id = s.zone_id,
            sys.scan_ip_ids = s.scan_ip_ids,
            sys.vip_ids = s.vip_ids,
            sys.private_ip = s.private_ip,
            sys.hostname = s.hostname,
            sys.domain = s.domain,
            sys.listener_port = s.listener_port,
            sys.cluster_name = s.cluster_name,
            sys.data_storage_percentage = s.data_storage_percentage,
            sys.kms_key_id = s.kms_key_id,
            sys.is_encrypted_with_cmk = s.is_encrypted_with_cmk,
            sys.ssh_public_key_count = s.ssh_public_key_count,
            sys.has_ssh_public_keys = s.has_ssh_public_keys,
            sys.data_safe_status = s.data_safe_status,
            sys.database_management_status = s.database_management_status,
            sys.iorm_lifecycle_state = s.iorm_lifecycle_state,
            sys.maintenance_window_preference = s.maintenance_window_preference,
            sys.region = s.region,
            sys.lastupdated = $oci_update_tag
        WITH sys
        MATCH (cc:OCICompartment{id: $COMPARTMENT_ID})
        MERGE (cc)-[r:RESOURCE]->(sys)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    neo4j_session.run(
        ingest_db_system,
        items=db_systems,
        COMPARTMENT_ID=compartment_id,
        oci_update_tag=oci_update_tag,
    )

    _link_subnet_and_nsg(
        neo4j_session,
        label="OCIDbSystem",
        items=db_systems,
        oci_update_tag=oci_update_tag,
    )
    _link_kms_key(
        neo4j_session,
        label="OCIDbSystem",
        items=db_systems,
        oci_update_tag=oci_update_tag,
    )


# ---------------------------------------------------------------------------
# DB Homes (one or more per DB System)
# ---------------------------------------------------------------------------

def get_db_home_list_data(
    database_client: oci.database.DatabaseClient,
    compartment_id: str,
    db_system_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    List DB Homes belonging to a single DB System. The OCI API requires the
    db_system_id to scope this call. See:
    https://docs.oracle.com/en-us/iaas/api/#/en/database/latest/DbHome/ListDbHomes
    """
    try:
        raw = _list_with_lifecycle_filter(
            database_client.list_db_homes,
            ACTIVE_DB_HOME_STATES,
            compartment_id=compartment_id,
            db_system_id=db_system_id,
        )
        return {'DbHomes': utils.oci_object_to_json(raw)}
    except Exception as e:
        logger.warning(
            "Could not retrieve DB Homes for system '%s': %s", db_system_id, e,
        )
        return {'DbHomes': []}


def transform_db_homes(
    db_homes: List[Dict[str, Any]],
    region: str,
) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for h in db_homes:
        if not h.get("id"):
            continue
        lifecycle_state = h.get("lifecycle-state")
        if lifecycle_state not in ACTIVE_DB_HOME_STATES:
            continue
        transformed.append({
            "ocid": h.get("id"),
            "id": h.get("id"),
            "display_name": h.get("display-name"),
            "compartment_id": h.get("compartment-id"),
            "db_system_id": h.get("db-system-id"),
            "vm_cluster_id": h.get("vm-cluster-id"),
            "db_version": h.get("db-version"),
            "db_home_location": h.get("db-home-location"),
            "lifecycle_state": lifecycle_state,
            "lifecycle_details": h.get("lifecycle-details"),
            "kms_key_id": h.get("kms-key-id"),
            "is_encrypted_with_cmk": bool(h.get("kms-key-id")),
            "last_patch_history_entry_id": h.get("last-patch-history-entry-id"),
            "time_created": str(h.get("time-created", "")),
            "region": region,
        })
    return transformed


def load_db_homes(
    neo4j_session: neo4j.Session,
    db_homes: List[Dict[str, Any]],
    oci_update_tag: int,
) -> None:
    """
    Ingest OCIDbHome nodes and attach each to its parent OCIDbSystem via
    HAS_DB_HOME. The DbSystem MATCH means homes for systems we did not load
    (e.g. a system in a state we filter out) silently no-op.
    """
    ingest_db_home = """
    UNWIND $items AS h
        MERGE (dh:OCIDbHome{id: h.id})
        ON CREATE SET dh.firstseen = timestamp(),
                      dh.createdate = h.time_created
        SET dh.ocid = h.ocid,
            dh.display_name = h.display_name,
            dh.compartment_id = h.compartment_id,
            dh.db_system_id = h.db_system_id,
            dh.vm_cluster_id = h.vm_cluster_id,
            dh.db_version = h.db_version,
            dh.db_home_location = h.db_home_location,
            dh.lifecycle_state = h.lifecycle_state,
            dh.lifecycle_details = h.lifecycle_details,
            dh.kms_key_id = h.kms_key_id,
            dh.is_encrypted_with_cmk = h.is_encrypted_with_cmk,
            dh.last_patch_history_entry_id = h.last_patch_history_entry_id,
            dh.region = h.region,
            dh.lastupdated = $oci_update_tag
        WITH dh, h
        MATCH (sys:OCIDbSystem{id: h.db_system_id})
        MERGE (sys)-[r:HAS_DB_HOME]->(dh)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    neo4j_session.run(
        ingest_db_home, items=db_homes, oci_update_tag=oci_update_tag,
    )

    _link_kms_key(
        neo4j_session,
        label="OCIDbHome",
        items=db_homes,
        oci_update_tag=oci_update_tag,
    )


# ---------------------------------------------------------------------------
# DB Nodes (one per VM in the system)
# ---------------------------------------------------------------------------

def get_db_node_list_data(
    database_client: oci.database.DatabaseClient,
    compartment_id: str,
    db_system_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    List DB Nodes for a DB System, server-side filtered. See:
    https://docs.oracle.com/en-us/iaas/api/#/en/database/latest/DbNode/ListDbNodes
    """
    try:
        raw = _list_with_lifecycle_filter(
            database_client.list_db_nodes,
            ACTIVE_DB_NODE_STATES,
            compartment_id=compartment_id,
            db_system_id=db_system_id,
        )
        return {'DbNodes': utils.oci_object_to_json(raw)}
    except Exception as e:
        logger.warning(
            "Could not retrieve DB Nodes for system '%s': %s", db_system_id, e,
        )
        return {'DbNodes': []}


def transform_db_nodes(
    db_nodes: List[Dict[str, Any]],
    region: str,
) -> List[Dict[str, Any]]:
    transformed: List[Dict[str, Any]] = []
    for n in db_nodes:
        if not n.get("id"):
            continue
        lifecycle_state = n.get("lifecycle-state")
        if lifecycle_state not in ACTIVE_DB_NODE_STATES:
            continue
        transformed.append({
            "ocid": n.get("id"),
            "id": n.get("id"),
            "hostname": n.get("hostname"),
            "compartment_id": n.get("compartment-id"),
            "db_system_id": n.get("db-system-id"),
            "vnic_id": n.get("vnic-id"),
            "backup_vnic_id": n.get("backup-vnic-id"),
            "host_ip_id": n.get("host-ip-id"),
            "backup_ip_id": n.get("backup-ip-id"),
            "fault_domain": n.get("fault-domain"),
            "lifecycle_state": lifecycle_state,
            "lifecycle_details": n.get("lifecycle-details"),
            "software_storage_size_in_gb": n.get("software-storage-size-in-gb"),
            "maintenance_type": n.get("maintenance-type"),
            "time_maintenance_window_start": str(
                n.get("time-maintenance-window-start", ""),
            ),
            "time_maintenance_window_end": str(
                n.get("time-maintenance-window-end", ""),
            ),
            "time_created": str(n.get("time-created", "")),
            "region": region,
        })
    return transformed


def load_db_nodes(
    neo4j_session: neo4j.Session,
    db_nodes: List[Dict[str, Any]],
    oci_update_tag: int,
) -> None:
    """
    Ingest OCIDbNode nodes and attach each to its parent OCIDbSystem via
    HAS_DB_NODE.
    """
    ingest_db_node = """
    UNWIND $items AS n
        MERGE (dn:OCIDbNode{id: n.id})
        ON CREATE SET dn.firstseen = timestamp(),
                      dn.createdate = n.time_created
        SET dn.ocid = n.ocid,
            dn.hostname = n.hostname,
            dn.compartment_id = n.compartment_id,
            dn.db_system_id = n.db_system_id,
            dn.vnic_id = n.vnic_id,
            dn.backup_vnic_id = n.backup_vnic_id,
            dn.host_ip_id = n.host_ip_id,
            dn.backup_ip_id = n.backup_ip_id,
            dn.fault_domain = n.fault_domain,
            dn.lifecycle_state = n.lifecycle_state,
            dn.lifecycle_details = n.lifecycle_details,
            dn.software_storage_size_in_gb = n.software_storage_size_in_gb,
            dn.maintenance_type = n.maintenance_type,
            dn.time_maintenance_window_start = n.time_maintenance_window_start,
            dn.time_maintenance_window_end = n.time_maintenance_window_end,
            dn.region = n.region,
            dn.lastupdated = $oci_update_tag
        WITH dn, n
        MATCH (sys:OCIDbSystem{id: n.db_system_id})
        MERGE (sys)-[r:HAS_DB_NODE]->(dn)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    neo4j_session.run(
        ingest_db_node, items=db_nodes, oci_update_tag=oci_update_tag,
    )


# ---------------------------------------------------------------------------
# Edge helpers (subnet / NSG / KMS) — MATCH-only, safe no-op
# ---------------------------------------------------------------------------

def _link_subnet_and_nsg(
    neo4j_session: neo4j.Session,
    label: str,
    items: List[Dict[str, Any]],
    oci_update_tag: int,
) -> None:
    """
    Attach each DB resource to its primary subnet and any NSGs. We use MATCH
    (not MERGE) on OCISubnet / OCINetworkSecurityGroup so this is a safe no-op
    if the network module hasn't run yet.
    """
    subnet_links = [
        {"resource_id": item["id"], "subnet_id": item.get("subnet_id")}
        for item in items if item.get("subnet_id")
    ]
    if subnet_links:
        link_subnet = f"""
        UNWIND $links AS link
            MATCH (r:{label}{{id: link.resource_id}})
            MATCH (s:OCISubnet{{id: link.subnet_id}})
            MERGE (r)-[rel:OCI_SUBNET]->(s)
            ON CREATE SET rel.firstseen = timestamp()
            SET rel.lastupdated = $oci_update_tag
        """
        neo4j_session.run(
            link_subnet, links=subnet_links, oci_update_tag=oci_update_tag,
        )

    nsg_links: List[Dict[str, str]] = []
    for item in items:
        for nsg_id in item.get("nsg_ids") or []:
            nsg_links.append({"resource_id": item["id"], "nsg_id": nsg_id})
    if nsg_links:
        link_nsg = f"""
        UNWIND $links AS link
            MATCH (r:{label}{{id: link.resource_id}})
            MATCH (n:OCINetworkSecurityGroup{{id: link.nsg_id}})
            MERGE (r)-[rel:OCI_NSG]->(n)
            ON CREATE SET rel.firstseen = timestamp()
            SET rel.lastupdated = $oci_update_tag
        """
        neo4j_session.run(
            link_nsg, links=nsg_links, oci_update_tag=oci_update_tag,
        )


def _link_kms_key(
    neo4j_session: neo4j.Session,
    label: str,
    items: List[Dict[str, Any]],
    oci_update_tag: int,
) -> None:
    """
    Connect each resource to its CMK on OCIKmsKey via OCI_KMS_KEY. MATCH-only
    so this is a safe no-op if the encryption module hasn't run.
    """
    links = [
        {"resource_id": item["id"], "kms_key_id": item.get("kms_key_id")}
        for item in items if item.get("kms_key_id")
    ]
    if not links:
        return
    link_kms = f"""
    UNWIND $links AS link
        MATCH (r:{label}{{id: link.resource_id}})
        MATCH (k:OCIKmsKey{{id: link.kms_key_id}})
        MERGE (r)-[rel:OCI_KMS_KEY]->(k)
        ON CREATE SET rel.firstseen = timestamp()
        SET rel.lastupdated = $oci_update_tag
    """
    neo4j_session.run(link_kms, links=links, oci_update_tag=oci_update_tag)


# ---------------------------------------------------------------------------
# DB System orchestration: one system → many homes + many nodes
# ---------------------------------------------------------------------------

def sync_db_systems(
    neo4j_session: neo4j.Session,
    database_client: oci.database.DatabaseClient,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    logger.debug(
        "Syncing OCI DB Systems for compartment '%s', region '%s'.",
        compartment_id, region,
    )
    raw_systems = get_db_system_list_data(database_client, compartment_id)["DbSystems"]
    db_systems = transform_db_systems(raw_systems, region)
    if not db_systems:
        return

    load_db_systems(neo4j_session, db_systems, compartment_id, oci_update_tag)

    all_homes: List[Dict[str, Any]] = []
    all_nodes: List[Dict[str, Any]] = []
    for sys in db_systems:
        sys_id = sys["id"]
        homes_raw = get_db_home_list_data(
            database_client, compartment_id, sys_id,
        )["DbHomes"]
        all_homes.extend(transform_db_homes(homes_raw, region))

        nodes_raw = get_db_node_list_data(
            database_client, compartment_id, sys_id,
        )["DbNodes"]
        all_nodes.extend(transform_db_nodes(nodes_raw, region))

    if all_homes:
        load_db_homes(neo4j_session, all_homes, oci_update_tag)
    if all_nodes:
        load_db_nodes(neo4j_session, all_nodes, oci_update_tag)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict[str, Any]) -> None:
    run_cleanup_job(
        'oci_import_database_cleanup.json', neo4j_session, common_job_parameters,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def sync(
    neo4j_session: neo4j.Session,
    database_client: oci.database.DatabaseClient,
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
    regions: Optional[List[str]] = None,
) -> None:
    """
    Sync OCI Database resources (Autonomous Database + Base DB System with
    Homes and Nodes) for the compartment in ``common_job_parameters``.
    Mirrors the per-region iteration used by compute / storage / oke.
    """
    compartment_id = common_job_parameters.get("OCI_COMPARTMENT_ID", tenancy_id)
    logger.info("Syncing OCI Database for compartment '%s'.", compartment_id)

    if not regions:
        regions = [database_client.base_client.region or ""]

    for region in regions:
        logger.info(
            "Syncing OCI Database in region '%s' for compartment '%s'.",
            region, compartment_id,
        )
        if region:
            database_client.base_client.set_region(region)

        try:
            sync_autonomous_databases(
                neo4j_session, database_client, compartment_id, region, oci_update_tag,
            )
        except Exception as e:
            logger.error("Error syncing OCI Autonomous Databases: %s", e, exc_info=True)

        try:
            sync_db_systems(
                neo4j_session, database_client, compartment_id, region, oci_update_tag,
            )
        except Exception as e:
            logger.error("Error syncing OCI DB Systems: %s", e, exc_info=True)

    cleanup(neo4j_session, common_job_parameters)
