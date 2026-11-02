from cartography.intel.gcp import firestore
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG


def test_indexes_link_only_databases_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    for project, database in ((OWN, 'fs-db-a'), (FOREIGN, 'fs-db-b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPFirestoreDatabase', database)

    firestore.load_firestore_indexes(
        neo4j_session, [{'id': f'{d}/ix', 'database_id': d} for d in ('fs-db-a', 'fs-db-b')], OWN, TAG,
    )

    assert sources(neo4j_session, 'HAS_INDEX', 'fs-db-a/ix') == {'fs-db-a'}
    assert sources(neo4j_session, 'HAS_INDEX', 'fs-db-b/ix') == set()
