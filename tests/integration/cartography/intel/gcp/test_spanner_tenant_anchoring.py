from cartography.intel.gcp import spanner
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG


def _seed(neo4j_session):
    # Each project: an instance on config sp-cfg-<t>, with config sp-config-<t> (replicas) and backup sp-backup-<t>.
    seed_tenants(neo4j_session)
    for project, t in ((OWN, 'a'), (FOREIGN, 'b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPSpannerInstance', f'sp-{t}', config=f'sp-cfg-{t}')
        put(neo4j_session, 'GCPSpannerInstance', f'sp-{t}', 'HAS', 'GCPSpannerInstanceConfig', f'sp-config-{t}')
        put(neo4j_session, 'GCPSpannerInstance', f'sp-{t}', 'HAS_BACKUP', 'GCPSpannerInstanceBackup', f'sp-backup-{t}')


def test_configs_replicas_backups_and_databases_link_only_inside_the_project(neo4j_session):
    _seed(neo4j_session)
    tenants = ('a', 'b')

    spanner.load_spanner_instance_configs(neo4j_session, [{'id': f'sp-cfg-{t}'} for t in tenants], OWN, TAG)
    spanner.load_spanner_instance_configs_replicas(
        neo4j_session, [{'id': f'sp-config-{t}/r', 'config': f'sp-config-{t}'} for t in tenants], OWN, TAG,
    )
    spanner.load_spanner_instances_backups(
        neo4j_session, [{'id': f'sp-{t}/new-backup', 'instance_id': f'sp-{t}'} for t in tenants], OWN, TAG,
    )
    # Each database names an instance and the backup it was restored from.
    spanner.load_spanner_instances_databases(
        neo4j_session,
        [
            {'id': 'sp-a/db-own', 'instance_id': 'sp-a', 'restoreInfo': {'backupInfo': {'backup': 'sp-backup-a'}}},
            {'id': 'sp-a/db-x', 'instance_id': 'sp-a', 'restoreInfo': {'backupInfo': {'backup': 'sp-backup-b'}}},
            {'id': 'sp-b/db-x', 'instance_id': 'sp-b', 'restoreInfo': {'backupInfo': {'backup': 'sp-backup-a'}}},
        ],
        OWN, TAG,
    )

    assert sources(neo4j_session, 'HAS', 'sp-cfg-a') == {'sp-a'}
    assert sources(neo4j_session, 'HAS', 'sp-cfg-b') == set()
    assert sources(neo4j_session, 'HAS', 'sp-config-a/r') == {'sp-config-a'}
    assert sources(neo4j_session, 'HAS', 'sp-config-b/r') == set()
    assert sources(neo4j_session, 'HAS_BACKUP', 'sp-a/new-backup') == {'sp-a'}
    assert sources(neo4j_session, 'HAS_BACKUP', 'sp-b/new-backup') == set()
    assert sources(neo4j_session, 'HAS_DATABASE', 'sp-a/db-own') == {'sp-a'}
    assert sources(neo4j_session, 'HAS_DATABASE', 'sp-b/db-x') == set()
    assert sources(neo4j_session, 'HAS_BACKUP', 'sp-backup-a') == {'sp-a', 'sp-a/db-own'}
    assert sources(neo4j_session, 'HAS_BACKUP', 'sp-backup-b') == {'sp-b'}
