from cartography.intel.gcp import bigtable
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG


def test_clusters_backups_and_tables_link_only_parents_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    for project, tenant in ((OWN, 'a'), (FOREIGN, 'b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPBigtableInstance', f'bt-i-{tenant}')
        put(
            neo4j_session, 'GCPBigtableInstance', f'bt-i-{tenant}', 'HAS_CLUSTER', 'GCPBigtableCluster',
            f'bt-c-{tenant}',
        )

    instances = ('bt-i-a', 'bt-i-b')
    bigtable.load_bigtable_clusters(
        neo4j_session, [{'id': f'{i}/c', 'instance_id': i} for i in instances], OWN, TAG,
    )
    bigtable.load_bigtable_tables(neo4j_session, [{'id': f'{i}/t', 'instance_id': i} for i in instances], OWN, TAG)
    bigtable.load_bigtable_cluster_backups(
        neo4j_session, [{'id': f'{c}/b', 'cluster_id': c} for c in ('bt-c-a', 'bt-c-b')], OWN, TAG,
    )

    assert sources(neo4j_session, 'HAS_CLUSTER', 'bt-i-a/c') == {'bt-i-a'}
    assert sources(neo4j_session, 'HAS_TABLE', 'bt-i-a/t') == {'bt-i-a'}
    assert sources(neo4j_session, 'HAS_BACKUP', 'bt-c-a/b') == {'bt-c-a'}
    assert sources(neo4j_session, 'HAS_CLUSTER', 'bt-i-b/c') == set()
    assert sources(neo4j_session, 'HAS_TABLE', 'bt-i-b/t') == set()
    assert sources(neo4j_session, 'HAS_BACKUP', 'bt-c-b/b') == set()
