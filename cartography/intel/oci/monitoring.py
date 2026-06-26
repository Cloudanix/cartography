# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI Monitoring, Events, Notifications, and Cloud Guard API-centric functions
import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j
import oci.cloud_guard
import oci.events
import oci.monitoring
import oci.ons

from . import utils
from cartography.client.core.tx import load_graph_data
from cartography.util import run_cleanup_job

logger = logging.getLogger(__name__)


# ============================================================
# Monitoring Alarms
# ============================================================

def get_alarm_list_data(
    monitoring: oci.monitoring.MonitoringClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all monitoring alarms in a compartment.
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            monitoring.list_alarms, compartment_id=compartment_id,
        )
        return {'Alarms': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve alarms for compartment '%s': %s",
            compartment_id, e.message,
        )
        return {'Alarms': []}


def load_alarms(
    neo4j_session: neo4j.Session,
    alarms: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Monitoring Alarm data into Neo4j.
    """
    ingest_alarm = """
    UNWIND $DictList AS alarm
        MERGE (a:OCIMonitoringAlarm{id: alarm.ocid})
        ON CREATE SET a.firstseen = timestamp()
        SET a.ocid = alarm.ocid,
        a.display_name = alarm.display_name,
        a.compartment_id = alarm.compartment_id,
        a.resource_type = 'oci-monitoring-alarm',
        a.namespace = alarm.namespace,
        a.query = alarm.query,
        a.severity = alarm.severity,
        a.is_enabled = alarm.is_enabled,
        a.lifecycle_state = alarm.lifecycle_state,
        a.metric_compartment_id = alarm.metric_compartment_id,
        a.destinations = alarm.destinations,
        a.region = $REGION,
        a.lastupdated = $oci_update_tag
        WITH a, alarm
        MATCH (cc:OCICompartment{id: alarm.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(a)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": alarm.get("id"),
            "display_name": alarm.get("display-name"),
            "compartment_id": alarm.get("compartment-id", compartment_id),
            "namespace": alarm.get("namespace", ""),
            "query": alarm.get("query", ""),
            "severity": alarm.get("severity", ""),
            "is_enabled": alarm.get("is-enabled", False),
            "lifecycle_state": alarm.get("lifecycle-state"),
            "metric_compartment_id": alarm.get("metric-compartment-id", ""),
            "destinations": alarm.get("destinations", []),
        }
        for alarm in alarms
    ]
    load_graph_data(
        neo4j_session, ingest_alarm, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_alarms(
    neo4j_session: neo4j.Session,
    monitoring: oci.monitoring.MonitoringClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    logger.debug("Syncing OCI monitoring alarms for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_alarm_list_data(monitoring, compartment["ocid"])
        if data["Alarms"]:
            load_alarms(
                neo4j_session, data["Alarms"], tenancy_id,
                compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# Cloud Guard
# ============================================================

def get_cloud_guard_configuration(
    cloud_guard: oci.cloud_guard.CloudGuardClient,
    compartment_id: str,
) -> Dict[str, Any]:
    """
    Get Cloud Guard configuration for a compartment (tenancy root).
    """
    try:
        response = cloud_guard.get_configuration(compartment_id=compartment_id)
        return utils.oci_single_object_to_json(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve Cloud Guard config for compartment '%s': %s",
            compartment_id, e.message,
        )
        return {}


def load_cloud_guard(
    neo4j_session: neo4j.Session,
    config_data: Dict[str, Any],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Cloud Guard configuration into Neo4j.
    """
    ingest_cg = """
    MERGE (cg:OCICloudGuard{id: $CONFIG_ID})
    ON CREATE SET cg.firstseen = timestamp()
    SET cg.ocid = $CONFIG_ID,
    cg.resource_type = 'oci-monitoring-cloud-guard',
    cg.compartment_id = $COMPARTMENT_ID,
    cg.status = $STATUS,
    cg.reporting_region = $REPORTING_REGION,
    cg.region = $REGION,
    cg.lastupdated = $oci_update_tag
    WITH cg
    MATCH (cc:OCICompartment{id: $COMPARTMENT_ID})
    MERGE (cc)-[r:RESOURCE]->(cg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $oci_update_tag
    """

    neo4j_session.run(
        ingest_cg,
        CONFIG_ID=f"oci.cloudguard.{compartment_id}.{region}",
        COMPARTMENT_ID=compartment_id,
        STATUS=config_data.get("status", "DISABLED"),
        REPORTING_REGION=config_data.get("reporting-region", ""),
        REGION=region,
        oci_update_tag=oci_update_tag,
    )


def sync_cloud_guard(
    neo4j_session: neo4j.Session,
    cloud_guard: oci.cloud_guard.CloudGuardClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    logger.debug("Syncing OCI Cloud Guard for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_cloud_guard_configuration(cloud_guard, compartment["ocid"])
        if data:
            load_cloud_guard(
                neo4j_session, data, tenancy_id,
                compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# Events Rules
# ============================================================

def get_event_rule_list_data(
    events: oci.events.EventsClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all event rules in a compartment.
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            events.list_rules, compartment_id=compartment_id,
        )
        return {'Rules': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve event rules for compartment '%s': %s",
            compartment_id, e.message,
        )
        return {'Rules': []}


def load_event_rules(
    neo4j_session: neo4j.Session,
    rules: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Events Rule data into Neo4j.
    """
    ingest_rule = """
    UNWIND $DictList AS rule
        MERGE (er:OCIEventRule{id: rule.ocid})
        ON CREATE SET er.firstseen = timestamp(),
        er.createdate = rule.time_created
        SET er.ocid = rule.ocid,
        er.display_name = rule.display_name,
        er.compartment_id = rule.compartment_id,
        er.resource_type = 'oci-monitoring-event-rule',
        er.condition = rule.condition,
        er.is_enabled = rule.is_enabled,
        er.lifecycle_state = rule.lifecycle_state,
        er.description = rule.description,
        er.region = $REGION,
        er.lastupdated = $oci_update_tag
        WITH er, rule
        MATCH (cc:OCICompartment{id: rule.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(er)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": rule.get("id"),
            "display_name": rule.get("display-name"),
            "compartment_id": rule.get("compartment-id", compartment_id),
            "condition": rule.get("condition", ""),
            "is_enabled": rule.get("is-enabled", False),
            "lifecycle_state": rule.get("lifecycle-state"),
            "description": rule.get("description", ""),
            "time_created": str(rule.get("time-created", "")),
        }
        for rule in rules
    ]
    load_graph_data(
        neo4j_session, ingest_rule, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_event_rules(
    neo4j_session: neo4j.Session,
    events: oci.events.EventsClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    logger.debug("Syncing OCI event rules for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_event_rule_list_data(events, compartment["ocid"])
        if data["Rules"]:
            load_event_rules(
                neo4j_session, data["Rules"], tenancy_id,
                compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# Notification Topics (ONS)
# ============================================================

def get_notification_topic_list_data(
    ons: oci.ons.NotificationControlPlaneClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all notification topics in a compartment.
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            ons.list_topics, compartment_id=compartment_id,
        )
        return {'Topics': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve notification topics for compartment '%s': %s",
            compartment_id, e.message,
        )
        return {'Topics': []}


def load_notification_topics(
    neo4j_session: neo4j.Session,
    topics: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Notification Topic data into Neo4j.
    """
    ingest_topic = """
    UNWIND $DictList AS topic
        MERGE (t:OCINotificationTopic{id: topic.ocid})
        ON CREATE SET t.firstseen = timestamp(),
        t.createdate = topic.time_created
        SET t.ocid = topic.ocid,
        t.display_name = topic.name,
        t.compartment_id = topic.compartment_id,
        t.resource_type = 'oci-monitoring-notification-topic',
        t.topic_id = topic.topic_id,
        t.lifecycle_state = topic.lifecycle_state,
        t.description = topic.description,
        t.api_endpoint = topic.api_endpoint,
        t.region = $REGION,
        t.lastupdated = $oci_update_tag
        WITH t, topic
        MATCH (cc:OCICompartment{id: topic.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(t)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": topic.get("topic-id", topic.get("id", "")),
            "name": topic.get("name", ""),
            "compartment_id": topic.get("compartment-id", compartment_id),
            "topic_id": topic.get("topic-id", ""),
            "lifecycle_state": topic.get("lifecycle-state"),
            "description": topic.get("description", ""),
            "api_endpoint": topic.get("api-endpoint", ""),
            "time_created": str(topic.get("time-created", "")),
        }
        for topic in topics
    ]
    load_graph_data(
        neo4j_session, ingest_topic, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_notification_topics(
    neo4j_session: neo4j.Session,
    ons: oci.ons.NotificationControlPlaneClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    logger.debug(
        "Syncing OCI notification topics for tenancy '%s', region '%s'.",
        tenancy_id, region,
    )
    for compartment in compartments:
        data = get_notification_topic_list_data(ons, compartment["ocid"])
        if data["Topics"]:
            load_notification_topics(
                neo4j_session, data["Topics"], tenancy_id,
                compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# Top-level sync function
# ============================================================

def sync(
    neo4j_session: neo4j.Session,
    monitoring: oci.monitoring.MonitoringClient,
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
    regions: List[str] = None,
) -> None:
    """
    Sync OCI Monitoring resources: Alarms, Cloud Guard, Event Rules,
    and Notification Topics.
    """
    compartment_ocid = common_job_parameters.get("OCI_COMPARTMENT_ID", tenancy_id)
    logger.info("Syncing OCI Monitoring for compartment '%s'.", compartment_ocid)

    compartments = [
        {"ocid": compartment_ocid, "name": "target", "compartmentid": tenancy_id},
    ]

    if not regions:
        regions = [monitoring.base_client.region or ""]

    # Create additional clients from the monitoring client's config/signer.
    cloud_guard = oci.cloud_guard.CloudGuardClient(
        config=monitoring.base_client.config,
        signer=getattr(monitoring.base_client, "signer", None),
    )
    events = oci.events.EventsClient(
        config=monitoring.base_client.config,
        signer=getattr(monitoring.base_client, "signer", None),
    )
    ons = oci.ons.NotificationControlPlaneClient(
        config=monitoring.base_client.config,
        signer=getattr(monitoring.base_client, "signer", None),
    )

    for region in regions:
        logger.info(
            "Syncing OCI Monitoring in region '%s' for compartment '%s'.",
            region, compartment_ocid,
        )
        monitoring.base_client.set_region(region)
        cloud_guard.base_client.set_region(region)
        events.base_client.set_region(region)
        ons.base_client.set_region(region)

        # Sync monitoring alarms
        sync_alarms(
            neo4j_session, monitoring, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

        # Sync Cloud Guard configuration
        sync_cloud_guard(
            neo4j_session, cloud_guard, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

        # Sync event rules
        sync_event_rules(
            neo4j_session, events, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

        # Sync notification topics
        sync_notification_topics(
            neo4j_session, ons, compartments, tenancy_id,
            region, oci_update_tag, common_job_parameters,
        )

    # Cleanup stale monitoring nodes
    run_cleanup_job(
        'oci_import_monitoring_cleanup.json', neo4j_session, common_job_parameters,
    )
