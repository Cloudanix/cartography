from cartography.intel.gcp import cloudfunction
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import put_principal
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG
from tests.integration.cartography.intel.gcp.common import tenant_params


def test_bindings_and_principals_link_only_functions_of_the_project(neo4j_session):
    seed_tenants(neo4j_session)
    put_principal(neo4j_session, 'a', 'cf@a.test')
    for project, function in ((OWN, 'cf-a'), (FOREIGN, 'cf-b')):
        put(neo4j_session, 'GCPProject', project, 'RESOURCE', 'GCPFunction', function)

    for function in ('cf-a', 'cf-b'):
        cloudfunction.attach_function_to_binding(
            neo4j_session, function, [{'id': f'{function}/binding', 'members': [], 'role': 'r'}], TAG, OWN,
        )
        cloudfunction.load_function_entity_relation(
            neo4j_session, {'id': function, 'entities': [{'email': 'cf@a.test'}]}, TAG, tenant_params(),
        )

    assert sources(neo4j_session, 'ATTACHED_BINDING', 'cf-a/binding') == {'cf-a'}
    assert sources(neo4j_session, 'USES', 'cf-a') == {'cf@a.test'}
    assert sources(neo4j_session, 'ATTACHED_BINDING', 'cf-b/binding') == set()
    assert sources(neo4j_session, 'USES', 'cf-b') == set()
