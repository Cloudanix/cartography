from cartography.intel.gcp import gke
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG


def test_node_pools_link_only_clusters_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    for project, cluster in ((OWN, 'gke-a'), (FOREIGN, 'gke-b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GKECluster', cluster)

    clusters = [{'id': c, 'name': c, 'location': 'r', 'nodePools': [{'name': 'pool'}]} for c in ('gke-a', 'gke-b')]
    gke.load_gke_node_pools(neo4j_session, clusters, OWN, TAG)

    assert sources(neo4j_session, 'HAS_NODE_POOL', 'gke-a/nodePools/pool') == {'gke-a'}
    assert sources(neo4j_session, 'HAS_NODE_POOL', 'gke-b/nodePools/pool') == set()
