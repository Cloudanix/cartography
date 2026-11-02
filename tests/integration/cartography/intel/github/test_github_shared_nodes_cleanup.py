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


def _seed_users(neo4j_session):
    # One GitHub user (keyed by profile URL) is in two tenants' orgs. Tenant A's stale OWNER edge still points at
    # the user, whose lastupdated is tenant B's tag. A second user has no edges left at all.
    neo4j_session.run(
        """
        MERGE (wa:CloudanixWorkspace{id: 'ws-usr-a'})-[:OWNER]->(oa:GitHubOrganization{id: 'org-usr-a'})
        MERGE (oa)-[:RESOURCE]->(repo:GitHubRepository{id: 'repo-usr-a'})
        MERGE (wb:CloudanixWorkspace{id: 'ws-usr-b'})-[:OWNER]->(ob:GitHubOrganization{id: 'org-usr-b'})
        MERGE (u:GitHubUser{id: 'https://github.com/shared-user'}) SET u.lastupdated = $other
        MERGE (u)-[o:OWNER]->(repo) SET o.lastupdated = $old
        MERGE (u)-[m:MEMBER_OF]->(ob) SET m.lastupdated = $other
        MERGE (gone:GitHubUser{id: 'https://github.com/departed-user'}) SET gone.lastupdated = $old
        """,
        old=OLD_TAG, other=OTHER_TENANT_TAG,
    )


def _user_links(neo4j_session):
    rows = neo4j_session.run(
        "MATCH (u:GitHubUser)-[r]->(n) WHERE u.id STARTS WITH 'https://github.com/' RETURN u.id AS u, type(r) AS r, "
        "n.id AS n",
    )
    return {(row['u'], row['r'], row['n']) for row in rows}


def test_users_cleanup_keeps_a_user_another_tenant_still_has(neo4j_session):
    _seed_users(neo4j_session)

    run_cleanup_job(
        'github_users_cleanup.json', neo4j_session,
        {'UPDATE_TAG': SYNC_TAG, 'WORKSPACE_ID': 'ws-usr-a', 'ORGANIZATION_ID': 'org-usr-a'},
    )

    # Tenant A's stale edge is gone; the user and its membership in tenant B's org survive.
    assert _user_links(neo4j_session) == {('https://github.com/shared-user', 'MEMBER_OF', 'org-usr-b')}


def test_users_orphan_sweep_deletes_only_unlinked_users(neo4j_session):
    run_cleanup_job('github_users_orphan_cleanup.json', neo4j_session, {'UPDATE_TAG': SYNC_TAG})

    rows = neo4j_session.run("MATCH (u:GitHubUser) WHERE u.id STARTS WITH 'https://github.com/' RETURN u.id AS id")
    assert {row['id'] for row in rows} == {'https://github.com/shared-user'}
