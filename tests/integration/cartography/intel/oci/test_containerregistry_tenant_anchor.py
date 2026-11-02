"""
Container registry lookups reach existing nodes only through the syncing tenancy
(AGENTS.md "Tenant isolation").
"""
import pytest

from cartography.intel.oci import containerregistry
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

REGION = 'us-phoenix-1'
TAG = 7


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    a, b = seed_tenancy(neo4j_session, 'ocir-a'), seed_tenancy(neo4j_session, 'ocir-b')
    for prefix, ids in (('ocir-a', a), ('ocir-b', b)):
        containerregistry.load_container_repositories(
            neo4j_session, [{'id': f'{prefix}-repo'}],
            ids['OCI_TENANCY_ID'], ids['OCI_COMPARTMENT_ID'], REGION, TAG,
        )
    return a, b


def test_repository_attaches_only_to_a_compartment_of_the_syncing_tenancy(neo4j_session, tenants):
    a, b = tenants
    containerregistry.load_container_repositories(
        neo4j_session, [{'id': 'a-repo-2', 'compartment-id': b['OCI_COMPARTMENT_ID']}],
        a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG,
    )
    assert linked(neo4j_session, a['OCI_COMPARTMENT_ID'], 'RESOURCE', 'ocir-a-repo')
    assert not linked(neo4j_session, b['OCI_COMPARTMENT_ID'], 'RESOURCE', 'a-repo-2')


def test_images_link_only_to_a_repository_of_the_syncing_tenancy(neo4j_session, tenants):
    a, _ = tenants
    containerregistry.load_container_images(
        neo4j_session,
        [{'id': 'a-image', 'repository-id': 'ocir-a-repo'}, {'id': 'a-image-foreign', 'repository-id': 'ocir-b-repo'}],
        a['OCI_TENANCY_ID'], a['OCI_COMPARTMENT_ID'], REGION, TAG,
    )
    assert linked(neo4j_session, 'ocir-a-repo', 'OCI_CONTAINER_IMAGE', 'a-image')
    assert not linked(neo4j_session, 'ocir-b-repo', 'OCI_CONTAINER_IMAGE', 'a-image-foreign')
