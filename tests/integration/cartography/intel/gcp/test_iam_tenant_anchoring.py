from cartography.intel.gcp import iam
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import TAG
from tests.integration.cartography.intel.gcp.common import tenant_params

PRINCIPAL = {'principal': 'user:eve@vendor-ta.example', 'access_type': 'ThirdParty', 'member_type': 'user'}


def test_external_principals_are_trusted_only_by_roles_of_the_granting_project(neo4j_session):
    seed_tenants(neo4j_session)
    own_org, other_org = tenant_params('a')['GCP_ORGANIZATION_ID'], tenant_params('b')['GCP_ORGANIZATION_ID']
    org_role, custom_role, foreign_role = (
        f'{own_org}/roles/viewer', f'projects/{OWN}/roles/custom', f'{other_org}/roles/viewer',
    )
    put(neo4j_session, 'GCPOrganization', own_org, 'RESOURCE', 'GCPRole', org_role)
    put(neo4j_session, 'GCPProject', OWN, 'RESOURCE', 'GCPRole', custom_role)
    put(neo4j_session, 'GCPOrganization', other_org, 'RESOURCE', 'GCPRole', foreign_role)

    for role in (org_role, custom_role, foreign_role):
        iam.load_gcp_external_principal(neo4j_session, role, PRINCIPAL, OWN, TAG)

    rows = neo4j_session.run(
        "MATCH (role:GCPRole)-[r:TRUSTS_GCP_PRINCIPAL]->(:GCPExternalPrincipal{principal: $p}) "
        "RETURN role.id AS role, r.account_id AS project",
        p=PRINCIPAL['principal'],
    )
    assert {(r['role'], r['project']) for r in rows} == {(org_role, OWN), (custom_role, OWN)}
