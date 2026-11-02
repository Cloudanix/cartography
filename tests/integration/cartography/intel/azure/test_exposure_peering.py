"""
Hub-spoke: an Application Gateway in the hub forwards to a private IP that two spokes reuse and
to a web app by custom host name. VNet peerings (read inline from virtual_networks.list_all) pick
the spoke the hub peers with; the host name resolves against ingested web apps (no DNS).
"""
import json

from cartography.intel.azure import exposure_layers
from cartography.intel.azure import function_app
from cartography.intel.azure import network
from cartography.intel.azure import network_gateways
from cartography.util import run_cleanup_job

TAG = 1700000000
WS, TENANT, SUB = 'ws-peer', 'tenant-peer', 'sub-peer'
PARAMS = {
    'UPDATE_TAG': TAG, 'WORKSPACE_ID': WS, 'AZURE_TENANT_ID': TENANT, 'AZURE_SUBSCRIPTION_ID': SUB,
    'LIMIT_SIZE': 1000,
}
REUSED_IP = '10.1.0.4'


def arm(kind, name):
    return f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/{kind}/{name}'


AGW_ID = arm('applicationGateways', 'agw-hub')
SITE_ID = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/shop'
HUB, SPOKE_A, SPOKE_B = (arm('virtualNetworks', v) for v in ('hub', 'spoke-a', 'spoke-b'))


def _vnets(session, tag=TAG):
    def vnet(vnet_id, peers):
        return {
            'id': vnet_id, 'name': vnet_id.rsplit('/', 1)[-1], 'virtual_network_peerings': [
                {
                    'id': f'{vnet_id}/virtualNetworkPeerings/to-{p.rsplit("/", 1)[-1]}',
                    'remote_virtual_network': {'id': p}, 'peering_state': 'Connected',
                    'allow_virtual_network_access': True,
                }
                for p in peers
            ],
        }
    rows = [vnet(HUB, [SPOKE_B]), vnet(SPOKE_A, []), vnet(SPOKE_B, [HUB])]
    for row in rows:
        network.add_peerings(row)
    network.load_networks(session, SUB, rows, tag)
    network.load_network_peerings(session, SUB, WS, rows, tag)


def _subnet(session, vnet_id, name, prefixes):
    subnet_id = f'{vnet_id}/subnets/{name}'
    network.load_networks_subnets(
        session, [{'id': subnet_id, 'name': name, 'network_id': vnet_id, 'address_prefixes': prefixes}], SUB, TAG,
    )
    return subnet_id


def _nic(session, name, subnet_id):
    nic_id = arm('networkInterfaces', name)
    nic = {
        'id': nic_id, 'name': name, 'location': 'eastus',
        'ip_configurations': [{'id': f'{nic_id}/ipConfigurations/ipconfig1', 'private_ip_address': REUSED_IP}],
        'subnet': [{'subnet_id': subnet_id}],
    }
    network.load_network_interfaces(session, SUB, [nic], TAG)
    network.load_ip_configurations(session, SUB, [nic], TAG)
    network.attach_subnet_to_network_interfaces(session, SUB, [nic], TAG)


def _app_gateway(session, subnet_id, addresses):
    """Public listener 443 -> pool of `addresses` (ip_address / fqdn) -> backend settings 8080."""
    def ref(path):
        return {'id': f'{AGW_ID}/{path}'}
    pip_id = arm('publicIPAddresses', 'agw-hub-pip')
    pip = {'id': pip_id, 'name': 'agw-hub-pip', 'ip_address': '20.9.0.1'}
    network.load_public_ip_addresses(session, SUB, [pip], TAG)
    gateway = {
        'id': AGW_ID, 'name': 'agw-hub', 'location': 'eastus',
        'gateway_ip_configurations': [{'id': f'{AGW_ID}/gic', 'subnet': {'id': subnet_id}}],
        'frontend_ip_configurations': [{'id': f'{AGW_ID}/fe', 'public_ip_address': {'id': pip_id}}],
        'frontend_ports': [{'id': f'{AGW_ID}/fp', 'port': 443}],
        'http_listeners': [{
            'id': f'{AGW_ID}/l', 'frontend_ip_configuration': ref('fe'), 'frontend_port': ref('fp'),
            'protocol': 'Https',
        }],
        'backend_address_pools': [{'id': f'{AGW_ID}/pool', 'backend_addresses': addresses}],
        'backend_http_settings_collection': [{'id': f'{AGW_ID}/s', 'port': 8080, 'protocol': 'Http'}],
        'request_routing_rules': [{
            'id': f'{AGW_ID}/rule', 'name': 'rule', 'http_listener': ref('l'),
            'backend_address_pool': ref('pool'), 'backend_http_settings': ref('s'),
        }],
    }
    network_gateways.load_application_gateways(
        session, SUB, WS, [network_gateways.transform_application_gateway(gateway, {})], TAG,
    )


def _build(session):
    session.run(
        "MERGE (w:CloudanixWorkspace{id: $ws}) MERGE (t:AzureTenant{id: $tenant}) "
        "MERGE (s:AzureSubscription{id: $sub}) MERGE (w)-[:OWNER]->(t) MERGE (t)-[:RESOURCE]->(s)",
        ws=WS, tenant=TENANT, sub=SUB,
    ).consume()
    _vnets(session)
    agw_subnet = _subnet(session, HUB, 'agw', ['10.0.50.0/24'])
    _nic(session, 'nic-a', _subnet(session, SPOKE_A, 'app', ['10.1.0.0/24']))
    _nic(session, 'nic-b', _subnet(session, SPOKE_B, 'app', ['10.1.0.0/24']))
    # Private-endpoint-only site: no direct path, reachable through the gateway.
    site = {
        'id': SITE_ID, 'name': 'shop', 'publicNetworkAccess': 'Disabled',
        'default_host_name': 'shop.azurewebsites.net', 'enabled_host_names': ['shop.contoso.com'],
    }
    function_app.load_function_apps(session, SUB, [site], TAG)
    _app_gateway(session, agw_subnet, [{'ip_address': REUSED_IP}, {'fqdn': 'Shop.Contoso.com'}])


def _reachable(session, label, node_id):
    query = f"MATCH (n:{label}{{id: $id}}) RETURN n.internet_reachable AS r, n.internet_reachable_via AS via"
    record = session.run(query, id=node_id).single()
    return record['r'], record['via']


def test_hub_gateway_resolves_reused_ip_in_peered_spoke(neo4j_session):
    _build(neo4j_session)
    exposure_layers.run(neo4j_session, PARAMS)

    nic = 'AzureNetworkInterface'
    assert _reachable(neo4j_session, nic, arm('networkInterfaces', 'nic-b')) == (True, [f'appgw:{AGW_ID}'])
    assert _reachable(neo4j_session, nic, arm('networkInterfaces', 'nic-a')) == (False, [])
    peering = neo4j_session.run(
        "MATCH (:AzureNetwork{id: $hub})-[r:PEERED_WITH]->(v:AzureNetwork) RETURN v.id AS v, r.peering_state AS s",
        hub=HUB,
    ).data()
    assert peering == [{'v': SPOKE_B, 's': 'Connected'}]
    stored = neo4j_session.run("MATCH (n:AzureNetwork{id: $id}) RETURN n.peered_network_ids AS p", id=HUB).single()
    assert stored['p'] == [SPOKE_B.lower()]


def test_hub_gateway_reaches_web_app_by_custom_host_name(neo4j_session):
    _build(neo4j_session)
    exposure_layers.run(neo4j_session, PARAMS)

    assert _reachable(neo4j_session, 'AzureFunctionApp', SITE_ID) == (True, [f'appgw:{AGW_ID}'])
    record = neo4j_session.run(
        "MATCH (n:AzureFunctionApp{id: $id}) RETURN n.internet_reachable_ports AS ports, n.exposure_paths AS paths",
        id=SITE_ID,
    ).single()
    assert record['ports'] == ['tcp:8080-8080']
    assert json.loads(record['paths'])[0]['hops'] == [
        {'hop': 'listener', 'id': f'{AGW_ID}/rule', 'rule': 'https 443 -> http 8080'},
        {'hop': 'service', 'id': SITE_ID},
    ]


def test_stale_peering_edge_is_cleaned(neo4j_session):
    _build(neo4j_session)
    rows = [{'id': HUB, 'name': 'hub', 'virtual_network_peerings': []}]
    network.add_peerings(rows[0])
    network.load_networks(neo4j_session, SUB, rows, TAG + 1)
    network.load_network_peerings(neo4j_session, SUB, WS, rows, TAG + 1)
    run_cleanup_job('azure_import_networks_cleanup.json', neo4j_session, {**PARAMS, 'UPDATE_TAG': TAG + 1})
    count = neo4j_session.run("MATCH (:AzureNetwork{id: $hub})-[r:PEERED_WITH]->() RETURN count(r) AS c", hub=HUB)
    assert count.single()['c'] == 0
