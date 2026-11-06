from cartography.intel.github import repos as github_repos
from cartography.intel.github import users as github_users
from cartography.intel.gitlab import members as gitlab_members

TAG = 1_793_600_000
USER_URL = 'https://github.com/edge-shared-user'


def _github_user(role):
    return {
        'node': {'url': USER_URL, 'login': 'edge-shared-user', 'name': 'Shared', 'isSiteAdmin': False},
        'hasTwoFactorEnabled': True, 'role': role, 'consolelink': USER_URL,
    }


def test_github_org_role_is_kept_per_org_on_the_member_of_edge(neo4j_session):
    # A legacy node still carries a role written on the shared node before this change.
    neo4j_session.run("MERGE (u:GitHubUser{id: $url}) SET u.role = 'ADMIN'", url=USER_URL)
    for org, ws, role in [('edge-org-a', 'edge-ws-a', 'ADMIN'), ('edge-org-b', 'edge-ws-b', 'MEMBER')]:
        github_users.load_organization_users(
            neo4j_session, [_github_user(role)], {'login': org, 'url': org},
            {'UPDATE_TAG': TAG, 'WORKSPACE_ID': ws},
        )

    rows = neo4j_session.run(
        "MATCH (u:GitHubUser{id: $url})-[r:MEMBER_OF]->(o:GitHubOrganization) RETURN o.id AS org, r.role AS role",
        url=USER_URL,
    )
    assert {(row['org'], row['role']) for row in rows} == {('edge-org-a', 'ADMIN'), ('edge-org-b', 'MEMBER')}
    node_role = neo4j_session.run("MATCH (u:GitHubUser{id: $url}) RETURN u.role AS role", url=USER_URL)
    assert node_role.single()['role'] is None


def test_github_collaborator_permission_is_kept_per_repo_on_the_edge(neo4j_session):
    neo4j_session.run(
        "UNWIND ['edge-repo-a', 'edge-repo-b'] AS id MERGE (:GitHubRepository{id: id}) "
        "MERGE (u:GitHubUser{id: $url}) SET u.permission = 'ADMIN'",
        url=USER_URL,
    )
    collaborators = {
        'DIRECT': [
            {
                'url': USER_URL, 'login': 'edge-shared-user', 'name': 'Shared', 'permission': perm,
                'email': None, 'company': None, 'repo_url': repo,
            } for repo, perm in [('edge-repo-a', 'ADMIN'), ('edge-repo-b', 'READ')]
        ],
    }

    github_repos.load_collaborators(neo4j_session, TAG, collaborators)

    rows = neo4j_session.run(
        "MATCH (u:GitHubUser{id: $url})-[r:OUTSIDE_COLLAB_DIRECT]->(repo) RETURN repo.id AS repo, "
        "r.permission AS permission, u.permission AS node_permission",
        url=USER_URL,
    )
    assert {(row['repo'], row['permission'], row['node_permission']) for row in rows} == {
        ('edge-repo-a', 'ADMIN', None), ('edge-repo-b', 'READ', None),
    }


def test_gitlab_membership_values_are_kept_per_group_on_the_member_edge(neo4j_session):
    neo4j_session.run("UNWIND ['edge-group-a', 'edge-group-b'] AS id MERGE (:GitLabGroup{id: id})")
    for group, level, state in [('edge-group-a', 50, 'active'), ('edge-group-b', 10, 'awaiting')]:
        member = {
            'node_id': 'edge-member', 'name': 'M', 'username': 'edge-member', 'state': 'active',
            'web_url': 'https://gitlab.com/edge-member', 'created_by': {'username': f'{group}-owner'},
            'access_level': level, 'avatar_url': None, 'public_email': None, 'expires_at': None,
            'group_id': group, 'locked': False, 'membership_state': state, 'consolelink': None,
            'created_at': None,
        }
        neo4j_session.execute_write(
            gitlab_members._load_members_data, [member], {'UPDATE_TAG': TAG}, group,
        )

    rows = neo4j_session.run(
        "MATCH (g:GitLabGroup)-[r:MEMBER]->(m:GitLabMember{id: 'edge-member'}) "
        "RETURN g.id AS g, r.access_level AS level, r.membership_state AS state, r.group_id AS gid, "
        "r.created_by AS by, m.access_level AS node_level, m.group_id AS node_gid",
    )
    assert {(r['g'], r['level'], r['state'], r['gid'], r['by'], r['node_level'], r['node_gid']) for r in rows} == {
        ('edge-group-a', 50, 'active', 'edge-group-a', 'edge-group-a-owner', None, None),
        ('edge-group-b', 10, 'awaiting', 'edge-group-b', 'edge-group-b-owner', None, None),
    }
