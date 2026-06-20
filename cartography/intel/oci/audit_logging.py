# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI Logging & Audit API-centric functions
#
# Covers:
#   - Audit Configuration              https://docs.oracle.com/en-us/iaas/Content/Audit/Concepts/auditoverview.htm
#   - Logging Log Groups               https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm
#   - Logging Logs                     https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm
#   - Logging Services                 https://docs.oracle.com/en-us/iaas/Content/Logging/Concepts/loggingoverview.htm
#   - Logging Configuration (overall)  Aggregated posture summary
#   - Object Storage Bucket (logging)  Enriches bucket nodes with logging status
#
# Resource type strings (used by logginghelper checks):
#   oci-audit-configuration            => Audit Configuration
#   oci-logging-log-group              => Log Group
#   oci-logging-service                => Logging Service (overall)
#   oci-logging-configuration          => Logging Configuration (overall)
#   oci-storage-objectstorage-bucket   => Object Storage Bucket (for logging check)
import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j
import oci
import oci.audit
import oci.logging
import oci.object_storage

from . import utils
from cartography.client.core.tx import load_graph_data
from cartography.util import run_cleanup_job

logger = logging.getLogger(__name__)


# ============================================================
# Audit Configuration (oci-audit-configuration)
# ============================================================

def get_audit_configuration(
    audit_client: oci.audit.AuditClient,
    tenancy_id: str,
) -> Dict[str, Any]:
    """
    Retrieve the tenancy-level audit configuration including the
    retention period. See:
    https://docs.oracle.com/en-us/iaas/api/#/en/audit/latest/Configuration/GetConfiguration
    """
    try:
        response = audit_client.get_configuration(compartment_id=tenancy_id)
        return utils.oci_single_object_to_json(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve audit configuration for tenancy '%s': %s",
            tenancy_id, e.message,
        )
        return {}


def load_audit_configuration(
    neo4j_session: neo4j.Session,
    config_data: Dict[str, Any],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Audit Configuration node into Neo4j.
    """
    ingest_audit_config = """
    MERGE (ac:OCIAuditConfiguration{id: $CONFIG_ID})
    ON CREATE SET ac.firstseen = timestamp()
    SET ac.ocid = $CONFIG_ID,
        ac.resource_type = 'oci-audit-configuration',
        ac.tenancy_id = $TENANCY_ID,
        ac.compartment_id = $COMPARTMENT_ID,
        ac.retention_period_days = $RETENTION_PERIOD_DAYS,
        ac.region = $REGION,
        ac.lastupdated = $oci_update_tag
    WITH ac
    MATCH (cc:OCICompartment{id: $COMPARTMENT_ID})
    MERGE (cc)-[r:RESOURCE]->(ac)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $oci_update_tag
    """
    retention = config_data.get("retention-period-days", 0)
    neo4j_session.run(
        ingest_audit_config,
        CONFIG_ID=f"oci.audit.config.{tenancy_id}.{region}",
        TENANCY_ID=tenancy_id,
        COMPARTMENT_ID=compartment_id,
        RETENTION_PERIOD_DAYS=retention,
        REGION=region,
        oci_update_tag=oci_update_tag,
    )


def sync_audit_configuration(
    neo4j_session: neo4j.Session,
    audit_client: oci.audit.AuditClient,
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """Fetch and load audit configuration for the tenancy."""
    logger.debug("Syncing OCI audit configuration for tenancy '%s'.", tenancy_id)
    data = get_audit_configuration(audit_client, tenancy_id)
    if data:
        load_audit_configuration(
            neo4j_session, data, tenancy_id, compartment_id, region, oci_update_tag,
        )


# ============================================================
# Logging Log Groups (oci-logging-log-group)
# ============================================================

def get_log_group_list_data(
    logging_client: oci.logging.LoggingManagementClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    List all log groups in a compartment. See:
    https://docs.oracle.com/en-us/iaas/api/#/en/logging-management/latest/LogGroup/ListLogGroups
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            logging_client.list_log_groups, compartment_id=compartment_id,
        )
        return {'LogGroups': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve log groups for compartment '%s': %s",
            compartment_id, e.message,
        )
        return {'LogGroups': []}


def get_logs_for_log_group(
    logging_client: oci.logging.LoggingManagementClient,
    log_group_id: str,
) -> List[Dict[str, Any]]:
    """
    List all logs within a given log group. See:
    https://docs.oracle.com/en-us/iaas/api/#/en/logging-management/latest/Log/ListLogs
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            logging_client.list_logs, log_group_id=log_group_id,
        )
        return utils.oci_object_to_json(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve logs for log group '%s': %s",
            log_group_id, e.message,
        )
        return []


def load_log_groups(
    neo4j_session: neo4j.Session,
    log_groups: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Log Group nodes into Neo4j.
    """
    ingest_log_group = """
    UNWIND $DictList AS lg
        MERGE (g:OCILogGroup{id: lg.ocid})
        ON CREATE SET g.firstseen = timestamp(),
                      g.createdate = lg.time_created
        SET g.ocid = lg.ocid,
            g.resource_type = 'oci-logging-log-group',
            g.display_name = lg.display_name,
            g.compartment_id = lg.compartment_id,
            g.description = lg.description,
            g.lifecycle_state = lg.lifecycle_state,
            g.region = $REGION,
            g.lastupdated = $oci_update_tag
        WITH g, lg
        MATCH (cc:OCICompartment{id: lg.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(g)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": lg.get("id"),
            "display_name": lg.get("display-name", ""),
            "compartment_id": lg.get("compartment-id", compartment_id),
            "description": lg.get("description", ""),
            "lifecycle_state": lg.get("lifecycle-state", ""),
            "time_created": str(lg.get("time-created", "")),
        }
        for lg in log_groups
    ]
    load_graph_data(
        neo4j_session, ingest_log_group, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def load_logs(
    neo4j_session: neo4j.Session,
    logs: List[Dict[str, Any]],
    log_group_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest individual OCI Log nodes within a log group.
    """
    ingest_log = """
    UNWIND $DictList AS log
        MERGE (l:OCILog{id: log.ocid})
        ON CREATE SET l.firstseen = timestamp(),
                      l.createdate = log.time_created
        SET l.ocid = log.ocid,
            l.resource_type = 'oci-logging-log',
            l.display_name = log.display_name,
            l.log_group_id = $LOG_GROUP_ID,
            l.log_type = log.log_type,
            l.is_enabled = log.is_enabled,
            l.lifecycle_state = log.lifecycle_state,
            l.retention_duration = log.retention_duration,
            l.compartment_id = log.compartment_id,
            l.source_service = log.source_service,
            l.source_resource = log.source_resource,
            l.source_category = log.source_category,
            l.region = $REGION,
            l.lastupdated = $oci_update_tag
        WITH l
        MATCH (lg:OCILogGroup{id: $LOG_GROUP_ID})
        MERGE (lg)-[r:OCI_LOG]->(l)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = []
    for log_entry in logs:
        config = log_entry.get("configuration", {}) or {}
        source = config.get("source", {}) or {}
        rows.append({
            "ocid": log_entry.get("id"),
            "display_name": log_entry.get("display-name", ""),
            "log_type": log_entry.get("log-type", ""),
            "is_enabled": log_entry.get("is-enabled", False),
            "lifecycle_state": log_entry.get("lifecycle-state", ""),
            "retention_duration": log_entry.get("retention-duration", 30),
            "compartment_id": log_entry.get("compartment-id", ""),
            "source_service": source.get("service", ""),
            "source_resource": source.get("resource", ""),
            "source_category": source.get("category", ""),
            "time_created": str(log_entry.get("time-created", "")),
        })

    load_graph_data(
        neo4j_session, ingest_log, rows,
        LOG_GROUP_ID=log_group_id, REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_log_groups(
    neo4j_session: neo4j.Session,
    logging_client: oci.logging.LoggingManagementClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """Fetch and load log groups and their child logs for each compartment."""
    logger.debug(
        "Syncing OCI log groups for tenancy '%s', region '%s'.", tenancy_id, region,
    )
    for compartment in compartments:
        data = get_log_group_list_data(logging_client, compartment["ocid"])
        log_groups = data.get("LogGroups", [])
        if log_groups:
            load_log_groups(
                neo4j_session, log_groups, tenancy_id,
                compartment["ocid"], region, oci_update_tag,
            )
            # For each log group, fetch and load its individual logs
            for lg in log_groups:
                lg_id = lg.get("id")
                if lg_id:
                    logs = get_logs_for_log_group(logging_client, lg_id)
                    if logs:
                        load_logs(neo4j_session, logs, lg_id, region, oci_update_tag)


# ============================================================
# Logging Services (oci-logging-service)
# ============================================================

def get_logging_service_list_data(
    logging_client: oci.logging.LoggingManagementClient,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    List all logging-enabled services. See:
    https://docs.oracle.com/en-us/iaas/api/#/en/logging-management/latest/ServiceSummary/ListServices
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            logging_client.list_services,
        )
        return {'Services': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve logging services: %s", e.message,
        )
        return {'Services': []}


def load_logging_services(
    neo4j_session: neo4j.Session,
    services: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Logging Service nodes into Neo4j.
    Each service represents a logging-capable OCI service (e.g., objectstorage, flowlogs).
    """
    ingest_service = """
    UNWIND $DictList AS svc
        MERGE (ls:OCILoggingService{id: svc.service_id})
        ON CREATE SET ls.firstseen = timestamp()
        SET ls.resource_type = 'oci-logging-service',
            ls.name = svc.name,
            ls.service_id = svc.service_id,
            ls.namespace = svc.namespace,
            ls.resource_types = svc.resource_types,
            ls.compartment_id = $COMPARTMENT_ID,
            ls.region = $REGION,
            ls.lastupdated = $oci_update_tag
        WITH ls
        MATCH (cc:OCICompartment{id: $COMPARTMENT_ID})
        MERGE (cc)-[r:RESOURCE]->(ls)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = []
    for svc in services:
        resource_types = []
        for rt in (svc.get("resource-types", []) or []):
            if isinstance(rt, dict):
                resource_types.append(rt.get("name", ""))
            elif isinstance(rt, str):
                resource_types.append(rt)

        svc_id = svc.get("id") or svc.get("service-type") or svc.get("name", "")
        rows.append({
            "service_id": f"oci.logging.service.{svc_id}.{region}",
            "name": svc.get("name", "") or svc.get("service-type", ""),
            "namespace": svc.get("namespace", ""),
            "resource_types": resource_types,
        })

    load_graph_data(
        neo4j_session, ingest_service, rows,
        COMPARTMENT_ID=compartment_id, REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_logging_services(
    neo4j_session: neo4j.Session,
    logging_client: oci.logging.LoggingManagementClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """Fetch and load available logging services."""
    logger.debug(
        "Syncing OCI logging services for tenancy '%s', region '%s'.", tenancy_id, region,
    )
    data = get_logging_service_list_data(logging_client)
    services = data.get("Services", [])
    if services:
        load_logging_services(
            neo4j_session, services, tenancy_id,
            compartments[0]["ocid"], region, oci_update_tag,
        )


# ============================================================
# Logging Configuration (oci-logging-configuration)
# Aggregated view summarizing logging posture for a compartment.
# ============================================================

def build_logging_configuration(
    log_groups: List[Dict[str, Any]],
    all_logs: List[Dict[str, Any]],
    audit_config: Dict[str, Any],
    compartment_id: str,
    region: str,
) -> Dict[str, Any]:
    """
    Build a synthetic logging configuration summary for the compartment,
    capturing overall posture metrics useful for CIS benchmark checks.
    """
    enabled_logs = [l for l in all_logs if l.get("is-enabled", False)]
    service_log_count = len([l for l in enabled_logs if l.get("log-type") == "SERVICE"])
    custom_log_count = len([l for l in enabled_logs if l.get("log-type") == "CUSTOM"])

    return {
        "compartment_id": compartment_id,
        "region": region,
        "total_log_groups": len(log_groups),
        "total_logs": len(all_logs),
        "enabled_logs": len(enabled_logs),
        "service_log_count": service_log_count,
        "custom_log_count": custom_log_count,
        "audit_retention_days": audit_config.get("retention-period-days", 0),
        "has_log_groups": len(log_groups) > 0,
        "has_enabled_logs": len(enabled_logs) > 0,
    }


def load_logging_configuration(
    neo4j_session: neo4j.Session,
    config: Dict[str, Any],
    tenancy_id: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest an aggregated OCI Logging Configuration node into Neo4j.
    """
    ingest_config = """
    MERGE (lc:OCILoggingConfiguration{id: $CONFIG_ID})
    ON CREATE SET lc.firstseen = timestamp()
    SET lc.resource_type = 'oci-logging-configuration',
        lc.compartment_id = $COMPARTMENT_ID,
        lc.region = $REGION,
        lc.total_log_groups = $TOTAL_LOG_GROUPS,
        lc.total_logs = $TOTAL_LOGS,
        lc.enabled_logs = $ENABLED_LOGS,
        lc.service_log_count = $SERVICE_LOG_COUNT,
        lc.custom_log_count = $CUSTOM_LOG_COUNT,
        lc.audit_retention_days = $AUDIT_RETENTION_DAYS,
        lc.has_log_groups = $HAS_LOG_GROUPS,
        lc.has_enabled_logs = $HAS_ENABLED_LOGS,
        lc.lastupdated = $oci_update_tag
    WITH lc
    MATCH (cc:OCICompartment{id: $COMPARTMENT_ID})
    MERGE (cc)-[r:RESOURCE]->(lc)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $oci_update_tag
    """

    config_id = f"oci.logging.config.{config['compartment_id']}.{config['region']}"
    neo4j_session.run(
        ingest_config,
        CONFIG_ID=config_id,
        COMPARTMENT_ID=config["compartment_id"],
        REGION=config["region"],
        TOTAL_LOG_GROUPS=config["total_log_groups"],
        TOTAL_LOGS=config["total_logs"],
        ENABLED_LOGS=config["enabled_logs"],
        SERVICE_LOG_COUNT=config["service_log_count"],
        CUSTOM_LOG_COUNT=config["custom_log_count"],
        AUDIT_RETENTION_DAYS=config["audit_retention_days"],
        HAS_LOG_GROUPS=config["has_log_groups"],
        HAS_ENABLED_LOGS=config["has_enabled_logs"],
        oci_update_tag=oci_update_tag,
    )


# ============================================================
# Object Storage Bucket — Logging Check (oci-storage-objectstorage-bucket)
# Enriches existing OCIStorageBucket nodes with write/read log enablement.
# ============================================================

def enrich_bucket_logging_status(
    neo4j_session: neo4j.Session,
    logging_client: oci.logging.LoggingManagementClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    For each OCI Storage Bucket in the compartment, check whether it has
    write or read logging enabled via the OCI Logging service and update
    the bucket node accordingly.
    """
    logger.debug(
        "Enriching bucket logging status for region '%s'.", region,
    )
    for compartment in compartments:
        compartment_id = compartment["ocid"]
        log_groups_data = get_log_group_list_data(logging_client, compartment_id)
        log_groups = log_groups_data.get("LogGroups", [])

        # Build map: bucket resource identifier -> set of log categories enabled
        bucket_log_categories: Dict[str, set] = {}
        for lg in log_groups:
            lg_id = lg.get("id")
            if not lg_id:
                continue
            logs = get_logs_for_log_group(logging_client, lg_id)
            for log_entry in logs:
                if not log_entry.get("is-enabled", False):
                    continue
                config = log_entry.get("configuration", {}) or {}
                source = config.get("source", {}) or {}
                if source.get("service", "").lower() == "objectstorage":
                    resource_id = source.get("resource", "")
                    category = source.get("category", "").lower()
                    if resource_id:
                        if resource_id not in bucket_log_categories:
                            bucket_log_categories[resource_id] = set()
                        bucket_log_categories[resource_id].add(category)

        # Update bucket nodes with logging status
        update_bucket_logging = """
        UNWIND $DictList AS bkt
            MATCH (b:OCIStorageBucket)
            WHERE b.compartment_id = $COMPARTMENT_ID AND b.region = $REGION
              AND (b.ocid = bkt.bucket_id OR b.name = bkt.bucket_id)
            SET b.write_logging_enabled = bkt.write_logging_enabled,
                b.read_logging_enabled = bkt.read_logging_enabled,
                b.logging_enabled = bkt.logging_enabled,
                b.logging_resource_type = 'oci-storage-objectstorage-bucket'
        """
        rows = []
        for bucket_id, categories in bucket_log_categories.items():
            write_enabled = "write" in categories
            read_enabled = "read" in categories
            rows.append({
                "bucket_id": bucket_id,
                "write_logging_enabled": write_enabled,
                "read_logging_enabled": read_enabled,
                "logging_enabled": (write_enabled or read_enabled),
            })
        load_graph_data(
            neo4j_session, update_bucket_logging, rows,
            COMPARTMENT_ID=compartment_id, REGION=region,
        )

        # Mark buckets without any logging as not enabled
        mark_unlogged_buckets = """
        MATCH (b:OCIStorageBucket)
        WHERE b.compartment_id = $COMPARTMENT_ID AND b.region = $REGION
          AND b.logging_enabled IS NULL
        SET b.write_logging_enabled = false,
            b.read_logging_enabled = false,
            b.logging_enabled = false,
            b.logging_resource_type = 'oci-storage-objectstorage-bucket'
        """
        neo4j_session.run(
            mark_unlogged_buckets,
            COMPARTMENT_ID=compartment_id,
            REGION=region,
        )


# ============================================================
# Top-level sync function
# ============================================================

def sync(
    neo4j_session: neo4j.Session,
    logging_mgmt: oci.logging.LoggingManagementClient,
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
    regions: List[str] = None,
) -> None:
    """
    Sync OCI Logging resources: Audit Configuration, Log Groups (with Logs),
    Logging Services, Logging Configuration summary, and Object Storage
    Bucket logging enrichment.
    """
    compartment_ocid = common_job_parameters.get("OCI_COMPARTMENT_ID", tenancy_id)
    logger.info("Syncing OCI Logging for compartment '%s'.", compartment_ocid)

    compartments = [
        {"ocid": compartment_ocid, "name": "target", "compartmentid": tenancy_id},
    ]

    if not regions:
        regions = [logging_mgmt.base_client.region or ""]

    # Create additional clients from the logging client's config/signer.
    audit_client = oci.audit.AuditClient(
        config=logging_mgmt.base_client.config,
        signer=getattr(logging_mgmt.base_client, "signer", None),
    )

    for region in regions:
        logger.info(
            "Syncing OCI Logging in region '%s' for compartment '%s'.",
            region, compartment_ocid,
        )
        logging_mgmt.base_client.set_region(region)
        audit_client.base_client.set_region(region)

        # 1. Audit Configuration
        sync_audit_configuration(
            neo4j_session, audit_client, tenancy_id,
            compartment_ocid, region, oci_update_tag, common_job_parameters,
        )

        # 2. Log Groups and their Logs
        sync_log_groups(
            neo4j_session, logging_mgmt, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

        # 3. Logging Services
        sync_logging_services(
            neo4j_session, logging_mgmt, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

        # 4. Logging Configuration (aggregated summary)
        all_log_groups: List[Dict[str, Any]] = []
        all_logs: List[Dict[str, Any]] = []
        for compartment in compartments:
            data = get_log_group_list_data(logging_mgmt, compartment["ocid"])
            log_groups = data.get("LogGroups", [])
            all_log_groups.extend(log_groups)
            for lg in log_groups:
                lg_id = lg.get("id")
                if lg_id:
                    logs = get_logs_for_log_group(logging_mgmt, lg_id)
                    all_logs.extend(logs)

        audit_config = get_audit_configuration(audit_client, tenancy_id)
        logging_config = build_logging_configuration(
            all_log_groups, all_logs, audit_config, compartment_ocid, region,
        )
        load_logging_configuration(neo4j_session, logging_config, tenancy_id, oci_update_tag)

        # 5. Object Storage Bucket logging enrichment
        enrich_bucket_logging_status(
            neo4j_session, logging_mgmt, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

    # Cleanup stale logging nodes
    run_cleanup_job('oci_import_logging_cleanup.json', neo4j_session, common_job_parameters)
