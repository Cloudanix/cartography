from cartography.intel.gcp import crm
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG
from tests.integration.cartography.intel.gcp.common import tenant_params


def test_folders_hang_only_off_an_organization_of_the_workspace(neo4j_session):
    seed_tenants(neo4j_session)
    own_org, other_org = tenant_params('a')['GCP_ORGANIZATION_ID'], tenant_params('b')['GCP_ORGANIZATION_ID']

    crm.load_gcp_folders(
        neo4j_session,
        [{'name': 'folders/ta-a', 'parent': own_org}, {'name': 'folders/ta-x', 'parent': other_org}],
        TAG, tenant_params('a'),
    )

    assert sources(neo4j_session, 'RESOURCE', 'folders/ta-a') == {own_org}
    assert sources(neo4j_session, 'RESOURCE', 'folders/ta-x') == set()
