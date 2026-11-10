from cartography.intel.gcp import crm
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import tenant_params


def test_reads_the_organization_of_the_workspace_project(neo4j_session):
    seed_tenants(neo4j_session)

    assert crm.read_project_organization_id(neo4j_session, 'ws-ta-a', OWN) == tenant_params('a')['GCP_ORGANIZATION_ID']


def test_never_reads_another_tenants_organization(neo4j_session):
    seed_tenants(neo4j_session)
    # The same project id also under tenant b's organization (a project both customers connected).
    neo4j_session.run(
        "MATCH (o:GCPOrganization{id: $org}) MATCH (p:GCPProject{id: $project}) MERGE (o)-[:OWNER]->(p)",
        org=tenant_params('b')['GCP_ORGANIZATION_ID'], project=OWN,
    )

    assert crm.read_project_organization_id(neo4j_session, 'ws-ta-a', OWN) == tenant_params('a')['GCP_ORGANIZATION_ID']
    assert crm.read_project_organization_id(neo4j_session, 'ws-ta-a', FOREIGN) is None
