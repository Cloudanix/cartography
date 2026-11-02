from cartography.util import run_cleanup_job

OLD_TAG = 1
OTHER_TENANT_TAG = 2
SYNC_TAG = 3


def _seed_repos(neo4j_session):
    # Two tenants' repos share the catalog nodes Python and "requests"; tenant A's repo alone used Go and "flask".
    # Tenant B synced last, so the shared nodes carry B's tag. Tenant A's repo has since dropped all four.
    neo4j_session.run(
        """
        UNWIND [['ws-cat-a', 'org-cat-a', 'repo-cat-a', $old], ['ws-cat-b', 'org-cat-b', 'repo-cat-b', $other]] AS t
        MERGE (w:CloudanixWorkspace{id: t[0]})
        MERGE (w)-[:OWNER]->(o:GitHubOrganization{id: t[1]})
        MERGE (o)-[r:RESOURCE]->(repo:GitHubRepository{id: t[2]})
        SET r.lastupdated = $sync, repo.lastupdated = $sync
        WITH repo, t
        UNWIND ['Python', 'Go'] AS name
        WITH repo, t, name WHERE name = 'Python' OR t[0] = 'ws-cat-a'
        MERGE (pl:ProgrammingLanguage{id: name}) SET pl.lastupdated = $other
        MERGE (repo)-[l:LANGUAGE]->(pl) SET l.lastupdated = t[3]
        WITH DISTINCT repo, t
        UNWIND ['requests', 'flask'] AS lib
        WITH repo, t, lib WHERE lib = 'requests' OR t[0] = 'ws-cat-a'
        MERGE (pylib:PythonLibrary:Dependency{id: lib}) SET pylib.lastupdated = $other
        MERGE (repo)-[q:REQUIRES]->(pylib) SET q.lastupdated = t[3]
        """,
        old=OLD_TAG, other=OTHER_TENANT_TAG, sync=SYNC_TAG,
    )


def _links(neo4j_session):
    rows = neo4j_session.run(
        """
        MATCH (repo:GitHubRepository)-[:LANGUAGE|REQUIRES]->(n)
        WHERE repo.id STARTS WITH 'repo-cat-'
        RETURN repo.id AS repo, n.id AS target
        """,
    )
    return {(row['repo'], row['target']) for row in rows}


def _catalog(neo4j_session):
    rows = neo4j_session.run(
        "MATCH (n) WHERE (n:ProgrammingLanguage OR n:PythonLibrary) AND n.id IN ['Python', 'Go', 'requests', 'flask'] "
        "RETURN n.id AS id",
    )
    return {row['id'] for row in rows}


def test_repo_cleanup_keeps_catalog_nodes_another_tenant_uses(neo4j_session):
    _seed_repos(neo4j_session)

    run_cleanup_job(
        'github_repos_cleanup.json', neo4j_session,
        {'UPDATE_TAG': SYNC_TAG, 'WORKSPACE_ID': 'ws-cat-a', 'ORGANIZATION_ID': 'org-cat-a'},
    )

    # Tenant A's stale edges are gone; tenant B's links to the shared nodes survive.
    assert _links(neo4j_session) == {('repo-cat-b', 'Python'), ('repo-cat-b', 'requests')}


def test_orphan_sweep_deletes_only_unlinked_catalog_nodes(neo4j_session):
    run_cleanup_job('github_repos_orphan_cleanup.json', neo4j_session, {'UPDATE_TAG': SYNC_TAG})

    assert _catalog(neo4j_session) == {'Python', 'requests'}
