from cartography.intel.gcp import workspace
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import TAG
from tests.integration.cartography.intel.gcp.common import tenant_params


def _members(neo4j_session, group_id):
    rows = neo4j_session.run(
        "MATCH (m)-[:MEMBER_GROUP]->(:GCPGroup{groupId: $g}) "
        "RETURN CASE WHEN m:GCPGroup THEN 'group:' + m.groupId ELSE 'user:' + m.userId END AS m",
        g=group_id,
    )
    return {r['m'] for r in rows}


def test_members_join_only_groups_of_the_workspace_organization(neo4j_session):
    seed_tenants(neo4j_session)
    for tenant in 'ab':
        org = tenant_params(tenant)['GCP_ORGANIZATION_ID']
        put(neo4j_session, 'GCPOrganization', org, 'RESOURCE', 'GCPGroup', f'eng-{tenant}@x', groupId=f'grp-{tenant}')
        put(neo4j_session, 'GCPOrganization', org, 'RESOURCE', 'GCPGroup', f'ops-{tenant}@x', groupId=f'sub-{tenant}')

    # Tenant a's directory lists a user and a nested group as members of its group and of tenant b's group id.
    for group in ('grp-a', 'grp-b'):
        workspace.load_groups_members(
            neo4j_session, {'id': group}, [{'id': 'user-1'}, {'id': 'sub-a'}, {'id': 'sub-b'}], TAG, tenant_params(),
        )

    # Every member id is also merged as a (shared) GCPUser; only the group-to-group link needs the tenant.
    assert _members(neo4j_session, 'grp-a') == {'user:user-1', 'user:sub-a', 'user:sub-b', 'group:sub-a'}
    assert _members(neo4j_session, 'grp-b') == set()
