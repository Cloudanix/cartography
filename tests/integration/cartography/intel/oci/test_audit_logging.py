# Copyright (c) 2020, Oracle and/or its affiliates.
import tests.data.oci.audit_logging as test_data
from cartography.intel.oci import audit_logging
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


def test_load_log_groups(neo4j_session):
    _seed_compartment(neo4j_session)
    audit_logging.load_log_groups(
        neo4j_session, test_data.LOG_GROUPS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCILogGroup", ["id", "display_name"]) == {
        ("oci.lg.0", "lg-0"),
    }
    assert (TEST_COMPARTMENT_ID, "oci.lg.0") in check_rels(
        neo4j_session, "OCICompartment", "id", "OCILogGroup", "id", "RESOURCE",
    )


def test_load_logs_links_log_group(neo4j_session):
    _seed_compartment(neo4j_session)
    audit_logging.load_log_groups(
        neo4j_session, test_data.LOG_GROUPS, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    audit_logging.load_logs(
        neo4j_session, test_data.LOGS, "oci.lg.0", TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCILog", ["id", "source_service"]) == {
        ("oci.log.0", "objectstorage"),
    }
    assert ("oci.lg.0", "oci.log.0") in check_rels(
        neo4j_session, "OCILogGroup", "id", "OCILog", "id", "OCI_LOG",
    )


def test_load_logging_services(neo4j_session):
    # Regression for Sentry CDX-CARTOGRAPHY-INVENTORY-887 crash site.
    _seed_compartment(neo4j_session)
    audit_logging.load_logging_services(
        neo4j_session, test_data.LOGGING_SERVICES, TEST_TENANCY_ID,
        TEST_COMPARTMENT_ID, TEST_REGION, TEST_UPDATE_TAG,
    )
    assert check_nodes(neo4j_session, "OCILoggingService", ["id", "name"]) == {
        ("oci.logging.service.objectstorage.us-phoenix-1", "Object Storage"),
    }
    assert (
        TEST_COMPARTMENT_ID, "oci.logging.service.objectstorage.us-phoenix-1",
    ) in check_rels(
        neo4j_session, "OCICompartment", "id", "OCILoggingService", "id", "RESOURCE",
    )
