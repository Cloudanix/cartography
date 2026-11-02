import cartography.intel.github.users
import tests.data.github.users

TEST_UPDATE_TAG = 123456789
common_job_parameters={'UPDATE_TAG':'123456789',"WORKSPACE_ID":"123445"}

def test_load_github_organization_users(neo4j_session):
    cartography.intel.github.users.load_organization_users(
        neo4j_session,
        tests.data.github.users.GITHUB_USER_DATA,
        tests.data.github.users.GITHUB_ORG_DATA,
        common_job_parameters,
    )

    # Ensure users got loaded
    nodes = neo4j_session.run(
        """
        MATCH (g:GitHubUser)-[r:MEMBER_OF]->(:GitHubOrganization) RETURN g.id, r.role, g.role;
        """,
    )
    # The org role lives on the org's MEMBER_OF edge; the shared user node carries none.
    expected_nodes = {
        ("https://example.com/hjsimpson", 'MEMBER', None),
        ("https://example.com/mbsimpson", 'ADMIN', None),
    }
    actual_nodes = {
        (
            n['g.id'],
            n['r.role'],
            n['g.role'],
        ) for n in nodes
    }
    assert actual_nodes == expected_nodes

    # Ensure users are connected to the expected organization
    nodes = neo4j_session.run(
        """
        MATCH(user:GitHubUser)-[:MEMBER_OF]->(org:GitHubOrganization)
        RETURN user.id, org.id
        """,
    )
    actual_nodes = {
        (
            n['user.id'],
            n['org.id'],
        ) for n in nodes
    }
    # GitHubOrganization is keyed by login.
    expected_nodes = {
        ('https://example.com/hjsimpson', 'my_org'),
        ('https://example.com/mbsimpson', 'my_org'),
    }
    assert actual_nodes == expected_nodes
