"""
Logging lookups reach existing nodes only through the syncing tenancy (AGENTS.md "Tenant isolation").
"""
from unittest.mock import MagicMock

import pytest

from cartography.intel.oci import audit_logging
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
TAG = 7


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    a, b = seed_tenancy(neo4j_session, 'log-a'), seed_tenancy(neo4j_session, 'log-b')
    for prefix, ids in (('log-a', a), ('log-b', b)):
        audit_logging.load_log_groups(
            neo4j_session, [{'id': f'{prefix}-lg', 'compartment-id': ids['OCI_COMPARTMENT_ID']}],
            ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID'], REGION, TAG,
        )
    return a, b


def test_log_groups_attach_only_to_a_compartment_of_the_syncing_tenancy(neo4j_session, tenants):
    a, b = tenants
    audit_logging.load_log_groups(
        neo4j_session, [{'id': 'a-lg-2', 'compartment-id': b['OCI_COMPARTMENT_ID']}],
        a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG,
    )
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'log-a-lg')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-lg-2')


def test_logs_link_only_to_a_log_group_of_the_syncing_tenancy(neo4j_session, tenants):
    a, _ = tenants
    audit_logging.load_logs(neo4j_session, [{'id': 'a-log'}], 'log-a-lg', a['OCI_TENANCY_ID'], REGION, TAG)
    audit_logging.load_logs(neo4j_session, [{'id': 'a-log-foreign'}], 'log-b-lg', a['OCI_TENANCY_ID'], REGION, TAG)
    assert linked(neo4j_session, 'log-a-lg', 'OCI_LOG', 'a-log')
    assert not linked(neo4j_session, 'log-b-lg', 'OCI_LOG', 'a-log-foreign')


def test_configuration_nodes_attach_only_inside_the_syncing_tenancy(neo4j_session, tenants):
    a, b = tenants
    tenancy = a['OCI_TENANCY_ID']
    # A compartment that is not in the syncing tenancy (a mismatched job parameter) finds nothing.
    for compartment in (a['OCI_COMPARTMENT_ID'], b['OCI_COMPARTMENT_ID']):
        audit_logging.load_audit_configuration(neo4j_session, {}, tenancy, compartment, REGION, TAG)
        audit_logging.load_logging_services(neo4j_session, [{'id': 'svc'}], tenancy, compartment, REGION, TAG)
        config = audit_logging.build_logging_configuration([], [], {}, compartment, REGION)
        audit_logging.load_logging_configuration(neo4j_session, config, tenancy, TAG)

    def config_ids(compartment):
        rows = neo4j_session.run(
            "MATCH (:OCICompartment{id: $c})-[:RESOURCE]->(n) "
            "WHERE n:OCIAuditConfiguration OR n:OCILoggingService OR n:OCILoggingConfiguration RETURN count(n) AS n",
            c=compartment,
        )
        return rows.single()['n']

    assert config_ids(a['OCI_COMPARTMENT_ID']) == 3
    assert config_ids(b['OCI_COMPARTMENT_ID']) == 0


def test_bucket_logging_status_is_written_only_to_the_syncing_tenancys_buckets(neo4j_session, tenants, monkeypatch):
    a, b = tenants
    # Tenancy B holds a bucket whose compartment_id property names tenancy A's compartment.
    neo4j_session.run(
        """
        UNWIND [[$a, 'a-bucket'], [$b, 'b-bucket']] AS pair
        MATCH (c:OCICompartment{id: pair[0]})
        MERGE (c)-[:RESOURCE]->(:OCIStorageBucket{
            id: pair[1], ocid: pair[1], name: pair[1], compartment_id: $a, region: $region})
        """,
        a=a['OCI_COMPARTMENT_ID'], b=b['OCI_COMPARTMENT_ID'], region=REGION,
    )
    monkeypatch.setattr(audit_logging, 'get_log_group_list_data', lambda *_: {'LogGroups': [{'id': 'lg'}]})
    monkeypatch.setattr(
        audit_logging, 'get_logs_for_log_group', lambda *_: [
            {
                'is-enabled': True,
                'configuration': {'source': {'service': 'objectstorage', 'resource': name, 'category': 'write'}},
            }
            for name in ('a-bucket', 'b-bucket')
        ],
    )
    audit_logging.enrich_bucket_logging_status(
        neo4j_session, MagicMock(), [{'ocid': a['OCI_COMPARTMENT_ID']}], a['OCI_TENANCY_ID'], REGION, TAG, a,
    )
    rows = neo4j_session.run("MATCH (b:OCIStorageBucket) RETURN b.id AS id, b.logging_enabled AS enabled")
    assert {row['id']: row['enabled'] for row in rows} == {'a-bucket': True, 'b-bucket': None}
