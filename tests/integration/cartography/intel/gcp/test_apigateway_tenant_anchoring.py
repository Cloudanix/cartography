from cartography.intel.gcp import apigateway
from tests.integration.cartography.intel.gcp.common import FOREIGN
from tests.integration.cartography.intel.gcp.common import OWN
from tests.integration.cartography.intel.gcp.common import put
from tests.integration.cartography.intel.gcp.common import put_principal
from tests.integration.cartography.intel.gcp.common import seed_tenants
from tests.integration.cartography.intel.gcp.common import sources
from tests.integration.cartography.intel.gcp.common import TAG
from tests.integration.cartography.intel.gcp.common import tenant_params


def _seed(neo4j_session):
    seed_tenants(neo4j_session)
    for project, api in ((OWN, 'ag-api-a'), (FOREIGN, 'ag-api-b')):
        put(neo4j_session, 'GCPProject', project, 'HAS_API_ENABLED', 'GCPAPI', api)
    for tenant in 'ab':
        put(neo4j_session, 'GCPAPI', f'ag-api-{tenant}', 'HAS_CONFIG', 'GCPAPIConfig', f'ag-cfg-{tenant}0')
        put(neo4j_session, 'GCPAPIConfig', f'ag-cfg-{tenant}0', 'HAS_GATEWAY', 'GCPAPIGateway', f'ag-gw-{tenant}0')
    put_principal(neo4j_session, 'a', 'ag@a.test')


def test_api_config_links_only_an_api_of_the_project(neo4j_session):
    _seed(neo4j_session)
    apigateway.load_api_configs(
        neo4j_session,
        [{'id': 'ag-cfg-a', 'api_id': 'ag-api-a'}, {'id': 'ag-cfg-x', 'api_id': 'ag-api-b'}],
        OWN, TAG,
    )
    assert sources(neo4j_session, 'HAS_CONFIG', 'ag-cfg-a') == {'ag-api-a'}
    assert sources(neo4j_session, 'HAS_CONFIG', 'ag-cfg-x') == set()


def test_gateway_links_only_a_config_of_the_project(neo4j_session):
    _seed(neo4j_session)
    apigateway.load_gateways(
        neo4j_session,
        [{'id': 'ag-gw-a', 'apiConfig': 'ag-cfg-a0'}, {'id': 'ag-gw-x', 'apiConfig': 'ag-cfg-b0'}],
        OWN, TAG,
    )
    assert sources(neo4j_session, 'HAS_GATEWAY', 'ag-gw-a') == {'ag-cfg-a0'}
    assert sources(neo4j_session, 'HAS_GATEWAY', 'ag-gw-x') == set()


def test_principals_use_only_apis_and_gateways_of_the_project(neo4j_session):
    _seed(neo4j_session)
    entities = [{'email': 'ag@a.test'}]
    for api in ('ag-api-a', 'ag-api-b'):
        apigateway.load_apis_entity_relation(neo4j_session, {'id': api, 'entities': entities}, TAG, tenant_params())
    for gateway in ('ag-gw-a0', 'ag-gw-b0'):
        apigateway.load_gateway_entity_relation(
            neo4j_session, {'id': gateway, 'entities': entities}, TAG, tenant_params(),
        )
    assert sources(neo4j_session, 'USES', 'ag-api-a') == {'ag@a.test'}
    assert sources(neo4j_session, 'USES', 'ag-gw-a0') == {'ag@a.test'}
    assert sources(neo4j_session, 'USES', 'ag-api-b') == set()
    assert sources(neo4j_session, 'USES', 'ag-gw-b0') == set()
