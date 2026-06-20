# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.monitoring as test_data
from cartography.intel.oci import monitoring
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_COMPARTMENT_ID = test_data.TEST_COMPARTMENT_ID
TEST_TENANCY_ID = test_data.TEST_TENANCY_ID
TEST_REGION = test_data.TEST_REGION
TEST_UPDATE_TAG = 123456789


def _seed_compartment(neo4j_session):
    neo4j_session.run(
        "MERGE (c:OCICompartment{id: $id}) SET c.lastupdated = $tag",
        id=TEST_COMPARTMENT_ID,
        tag=TEST_UPDATE_TAG,
    )


def test_load_alarms(neo4j_session):
    _seed_compartment(neo4j_session)
    monitoring.load_alarms(
        neo4j_session, test_data.ALARMS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIMonitoringAlarm", ["id"]) == {("oci.alarm.0",)}
    assert (TEST_COMPARTMENT_ID, "oci.alarm.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCIMonitoringAlarm", "id", "RESOURCE",
    )


def test_load_event_rules(neo4j_session):
    _seed_compartment(neo4j_session)
    monitoring.load_event_rules(
        neo4j_session, test_data.EVENT_RULES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCIEventRule", ["id"]) == {("oci.rule.0",)}
    assert (TEST_COMPARTMENT_ID, "oci.rule.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCIEventRule", "id", "RESOURCE",
    )


def test_load_notification_topics(neo4j_session):
    _seed_compartment(neo4j_session)
    monitoring.load_notification_topics(
        neo4j_session, test_data.NOTIFICATION_TOPICS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCINotificationTopic", ["id", "display_name"]) == {
        ("oci.topic.0", "topic-0"),
    }
    assert (TEST_COMPARTMENT_ID, "oci.topic.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCINotificationTopic", "id", "RESOURCE",
    )
