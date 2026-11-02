import pytest

from cartography.util import run_cleanup_job

ORPHAN_GRACE = 86400
SYNC_TAG = 1_793_600_000


@pytest.mark.parametrize(
    'label, job', [
        ('GitHubUser', 'github_users_orphan_cleanup.json'),
        ('ProgrammingLanguage', 'github_repos_orphan_cleanup.json'),
        ('PythonLibrary', 'github_repos_orphan_cleanup.json'),
        ('GitLabMember', 'gitlab_members_orphan_cleanup.json'),
        ('GitLabProject', 'gitlab_projects_orphan_cleanup.json'),
        ('AzureDevOpsUser', 'azure_devops_members_orphan_cleanup.json'),
    ],
)
def test_orphan_sweep_spares_a_node_another_worker_just_wrote(neo4j_session, label, job):
    # 'fresh' stands for a shared node another worker's sync has written but not linked yet; the sweep must
    # leave it alone. 'stale' has had no link and no write for longer than the grace window.
    neo4j_session.run(
        f"""
        MERGE (fresh:{label}{{id: 'scm-sweep-fresh'}}) SET fresh.lastupdated = $fresh_tag
        MERGE (stale:{label}{{id: 'scm-sweep-stale'}}) SET stale.lastupdated = $old_tag
        """,
        fresh_tag=SYNC_TAG - 60, old_tag=SYNC_TAG - 2 * ORPHAN_GRACE,
    )

    run_cleanup_job(job, neo4j_session, {'UPDATE_TAG': SYNC_TAG})

    left = {
        row['id'] for row in neo4j_session.run(
            f"MATCH (n:{label}) WHERE n.id STARTS WITH 'scm-sweep-' RETURN n.id AS id",
        )
    }
    assert left == {'scm-sweep-fresh'}
    neo4j_session.run(f"MATCH (n:{label}) WHERE n.id STARTS WITH 'scm-sweep-' DELETE n")
