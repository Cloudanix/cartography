"""
Monitoring loaders attach only to a compartment of the syncing tenancy (AGENTS.md "Tenant isolation"):
a compartment id from tenancy A's API data (or job parameters) that belongs to tenancy B finds nothing.
"""
import pytest

from cartography.intel.oci import monitoring
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
TAG = 7


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    return seed_tenancy(neo4j_session, 'mon-a'), seed_tenancy(neo4j_session, 'mon-b')


@pytest.mark.parametrize(
    'loader', [monitoring.load_alarms, monitoring.load_event_rules, monitoring.load_notification_topics],
)
def test_listed_resources_attach_only_inside_the_syncing_tenancy(neo4j_session, tenants, loader):
    a, b = tenants
    args = (a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG)
    loader(neo4j_session, [{'id': 'a-own', 'compartment-id': a['OCI_COMPARTMENT_ID']}], *args)
    loader(neo4j_session, [{'id': 'a-foreign', 'compartment-id': b['OCI_COMPARTMENT_ID']}], *args)
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-own')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-foreign')


def test_cloud_guard_attaches_only_inside_the_syncing_tenancy(neo4j_session, tenants):
    a, b = tenants
    monitoring.load_cloud_guard(neo4j_session, {}, a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG)
    monitoring.load_cloud_guard(neo4j_session, {}, a['OCI_TENANCY_ID'], b['OCI_COMPARTMENT_ID'], REGION, TAG)
    own = f"oci.cloudguard.{a['OCI_COMPARTMENT_ID']}.{REGION}"
    foreign = f"oci.cloudguard.{b['OCI_COMPARTMENT_ID']}.{REGION}"
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', own)
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', foreign)
