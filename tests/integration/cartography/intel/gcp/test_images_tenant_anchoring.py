from cartography.client.core.tx import load_graph_data
from cartography.intel.gcp import images
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants


def _regions(neo4j_session):
    rows = neo4j_session.run("MATCH (i:GCPImage) WHERE i.id STARTS WITH 'img-' RETURN i.id AS id, i.region AS region")
    return {r['id']: r['region'] for r in rows}


def test_image_region_is_set_only_on_images_the_project_owns_or_uses(neo4j_session):
    seed_tenants(neo4j_session)
    put(neo4j_session, 'GCPProject', OWN, 'RESOURCE', 'GCPImage', 'img-own')
    put(neo4j_session, 'GCPProject', OWN, 'RESOURCE', 'GCPInstance', 'img-vm')
    put(neo4j_session, 'GCPInstance', 'img-vm', 'HAS', 'GCPImage', 'img-public')
    put(neo4j_session, 'GCPProject', FOREIGN, 'RESOURCE', 'GCPImage', 'img-foreign')

    rows = [{'image_id': i, 'region': 'us-east1'} for i in ('img-own', 'img-public', 'img-foreign')]
    load_graph_data(neo4j_session, images._SET_IMAGE_REGION_QUERY, rows, ProjectId=OWN)

    assert _regions(neo4j_session) == {'img-own': 'us-east1', 'img-public': 'us-east1', 'img-foreign': None}
