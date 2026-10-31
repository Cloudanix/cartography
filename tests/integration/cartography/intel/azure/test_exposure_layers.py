"""
End-to-end check of the Azure exposure layers on a graph written by the Azure loaders
(network) or shaped like them (compute, PaaS). Scenarios follow docs/exposure-layers/plan.md
section 8.
"""
from cartography.intel.azure import exposure_layers
from cartography.intel.azure import network
from cartography.util import run_cleanup_job

TAG = 1700000000
WS, TENANT, SUB = 'ws-axl', 'tenant-axl', 'sub-axl'
OTHER_WS, OTHER_TENANT, OTHER_SUB = 'ws-axl-other', 'tenant-axl-other', 'sub-axl-other'
PARAMS = {
    'UPDATE_TAG': TAG, 'WORKSPACE_ID': WS, 'AZURE_TENANT_ID': TENANT, 'AZURE_SUBSCRIPTION_ID': SUB,
    'LIMIT_SIZE': 1000,
}
VNET = 'vnet1'


def arm(kind, name, sub=SUB):
    return f'/subscriptions/{sub}/resourceGroups/rg/providers/Microsoft.Network/{kind}/{name}'


def _run(session, query, **kw):
    session.run(query, **kw).consume()


def _scope(session, ws, tenant, sub):
    _run(
        session,
        "MERGE (w:CloudanixWorkspace{id: $ws}) MERGE (t:AzureTenant{id: $tenant}) "
        "MERGE (s:AzureSubscription{id: $sub}) MERGE (w)-[:OWNER]->(t) MERGE (t)-[:RESOURCE]->(s)",
        ws=ws, tenant=tenant, sub=sub,
    )


def _nsg(session, name, rules):
    """rules: (priority, access, source, ports, protocol)."""
    nsg_id = arm('networkSecurityGroups', name)
    nsg = {
        'id': nsg_id, 'name': name, 'location': 'eastus',
        'security_rules': [
            {
                'id': f'{nsg_id}/securityRules/r{i}', 'name': f'r{i}', 'access': access, 'direction': 'Inbound',
                'priority': priority, 'protocol': protocol, 'source_address_prefix': source,
                'source_address_prefixes': [], 'destination_port_range': ports, 'destination_address_prefix': '*',
            }
            for i, (priority, access, source, ports, protocol) in enumerate(rules)
        ],
    }
    network.load_network_security_groups(session, SUB, [nsg], TAG)
    network.load_network_security_rules(session, network.get_network_security_rules_list([nsg], None, {}), TAG)


def _subnet(session, name, nsg=None, udr_hop=None):
    subnet_id = arm('virtualNetworks', f'{VNET}/subnets/{name}')
    network.load_networks_subnets(
        session, [{
            'id': subnet_id, 'name': name, 'network_id': arm('virtualNetworks', VNET),
            'network_security_group_id': arm('networkSecurityGroups', nsg) if nsg else None,
        }], SUB, TAG,
    )
    if udr_hop:
        table = {'id': arm('routeTables', f'rt-{name}'), 'name': f'rt-{name}', 'subnets': [{'id': subnet_id}]}
        network.load_network_routetables(session, SUB, [table], TAG)
        network.attach_network_routetables_to_subnet(session, [table], TAG)
        network.load_network_routes(
            session, [{
                'id': f"{table['id']}/routes/default", 'name': 'default', 'routetable_id': table['id'],
                'address_prefix': '0.0.0.0/0', 'next_hop_type': udr_hop,
            }], TAG,
        )
    return subnet_id


def _nic(session, name, subnet_id, nsg=None, public_ip=None, sku=None):
    nic_id = arm('networkInterfaces', name)
    nic = {
        'id': nic_id, 'name': name, 'location': 'eastus',
        'network_security_group': {'id': arm('networkSecurityGroups', nsg)} if nsg else None,
        'ip_configurations': [{'id': f'{nic_id}/ipConfigurations/ipconfig1', 'private_ip_address': '10.0.0.4'}],
        'subnet': [{'subnet_id': subnet_id}],
    }
    network.load_network_interfaces(session, SUB, [nic], TAG)
    network.load_ip_configurations(session, [nic], TAG)
    network.attach_subnet_to_network_interfaces(session, [nic], TAG)
    if public_ip:
        pip_id = arm('publicIPAddresses', f'{name}-pip')
        pip = {'id': pip_id, 'name': f'{name}-pip', 'ip_address': public_ip, 'sku': {'name': sku}}
        network.load_public_ip_addresses(session, SUB, [pip], TAG)
        network.load_public_ip_network_interfaces_relationship(session, nic_id, [{'public_ip_id': pip_id}], TAG)
    return nic_id


def _vm(session, name, nic_id, offer=None, sku=None):
    _run(
        session,
        "MATCH (s:AzureSubscription{id: $sub}), (n:AzureNetworkInterface{id: $nic}) "
        "MERGE (s)-[:RESOURCE]->(vm:AzureVirtualMachine{id: $id}) SET vm.offer = $offer, vm.sku = $sku "
        "MERGE (vm)-[:MEMBER_NETWORK_INTERFACE]->(n)",
        sub=SUB, nic=nic_id, id=f'vm-{name}', offer=offer, sku=sku,
    )


def _load_balancer(session, backend_nic_id):
    lb_id = arm('loadBalancers', 'lb1')
    pip_id = arm('publicIPAddresses', 'lb1-pip')
    frontend = f'{lb_id}/frontendIPConfigurations/fe'
    pool = f'{lb_id}/backendAddressPools/web'
    ipconfig = f'{backend_nic_id}/ipConfigurations/ipconfig1'
    lb = {
        'id': lb_id, 'name': 'lb1', 'location': 'eastus', 'sku': {'name': 'Standard'},
        'frontend_ip_configurations': [{'id': frontend, 'public_ip_address': {'id': pip_id}}],
        'backend_address_pools': [{'id': pool, 'backend_ip_configurations': [{'id': ipconfig}]}],
        'load_balancing_rules': [{
            'id': f'{lb_id}/loadBalancingRules/https', 'protocol': 'Tcp', 'frontend_port': 443, 'backend_port': 8080,
            'frontend_ip_configuration': {'id': frontend}, 'backend_address_pool': {'id': pool},
        }],
        # SSH NAT to the same NIC: its NSG does not admit 22, so this path stays closed.
        'inbound_nat_rules': [{
            'id': f'{lb_id}/inboundNatRules/ssh', 'protocol': 'Tcp', 'frontend_port': 50001, 'backend_port': 22,
            'frontend_ip_configuration': {'id': frontend}, 'backend_ip_configuration': {'id': ipconfig},
        }],
    }
    lb['rules'] = network._load_balancer_rules(lb)
    network.load_public_ip_addresses(session, SUB, [{'id': pip_id, 'name': 'lb1-pip', 'ip_address': '20.9.9.9'}], TAG)
    network.load_load_balancers(session, SUB, [lb], TAG)
    network.load_backend_address_pools(session, [lb], TAG)
    network.load_frontend_ip_configurations(session, [lb], TAG)
    network.load_load_balancer_rules(session, [lb], TAG)
    network.create_relationship_between_network_interface_and_load_balancer(session, [lb], TAG)
    return lb_id


def _paas(session):
    _run(
        session,
        """
        MATCH (s:AzureSubscription{id: $sub})
        MERGE (s)-[:RESOURCE]->(open:AzureStorageAccount{id: 'st-open'})
        SET open.networkRuleDefaultAction = 'Allow', open.allowBlobPublicAccess = true
        MERGE (open)-[:USES]->(bs:AzureStorageBlobService{id: 'st-open/blob'})
        MERGE (bs)-[:CONTAINS]->(:AzureStorageBlobContainer{id: 'st-open/public', publicaccess: 'container'})
        MERGE (bs)-[:CONTAINS]->(:AzureStorageBlobContainer{id: 'st-open/private', publicaccess: 'none'})
        MERGE (s)-[:RESOURCE]->(fw:AzureStorageAccount{id: 'st-firewalled'})
        SET fw.networkRuleDefaultAction = 'Deny', fw.publicNetworkAccess = 'Enabled'
        MERGE (s)-[:RESOURCE]->(sql:AzureSQLServer{id: 'sql-world'})
        SET sql.publicNetworkAccess = 'Enabled', sql.engine = 'postgres', sql.engineVersion = '15', sql.port = 5432,
            sql.firewall_rules_fetched = true, sql.azureADOnlyAuthentication = true
        MERGE (sql)-[:HAS]->(:AzureFirewallRule{id: 'sql-world/all', start_ip_address: '0.0.0.0',
            end_ip_address: '255.255.255.255', address_count: 4294967296})
        MERGE (sql)-[:RESOURCE]->(:AzureSQLDatabase{id: 'sql-world/db1'})
        MERGE (s)-[:RESOURCE]->(office:AzureSQLServer{id: 'sql-office'})
        SET office.publicNetworkAccess = 'Enabled', office.engine = 'sqlserver', office.port = 1433,
            office.firewall_rules_fetched = true
        MERGE (office)-[:HAS]->(:AzureFirewallRule{id: 'sql-office/vm', start_ip_address: '20.1.1.0',
            end_ip_address: '20.1.1.255', address_count: 256})
        MERGE (s)-[:RESOURCE]->(:AzureCosmosDBAccount{id: 'cosmos-open', kind: 'GlobalDocumentDB', iprulecount: 0})
        MERGE (s)-[:RESOURCE]->(:AzureCosmosDBAccount{id: 'cosmos-filtered', iprulecount: 1,
            ipranges: ['30.0.0.0/24'], disableLocalAuth: true})
        MERGE (s)-[:RESOURCE]->(:AzureKeyVault{id: 'kv-off', public_network_access: 'Disabled'})
        MERGE (s)-[:RESOURCE]->(:AzureCluster{id: 'aks-public', authorizedIPRanges: [], kubernetesVersion: '1.29.4'})
        MERGE (s)-[:RESOURCE]->(:AzureCluster{id: 'aks-private', enablePrivateCluster: true})
        MERGE (s)-[:RESOURCE]->(:AzureContainerRegistry{id: 'acr-anon', anonymous_pull_enabled: true})
        MERGE (s)-[:RESOURCE]->(fn:AzureFunctionApp{id: 'fn-open'})
        MERGE (fn)-[:CONTAIN]->(:AzureFunctionAppConfiguration{id: 'fn-open/web', linux_fx_version: 'PYTHON|3.11'})
        MERGE (s)-[:RESOURCE]->(:AzureVirtualMachineScaleSet{id: 'vmss-pip', public_ip_per_instance: true,
            nsg_ids: [toLower($nsg_ssh)], subnet_ids: []})
        """,
        sub=SUB, nsg_ssh=arm('networkSecurityGroups', 'nsg-ssh'),
    )


def _build(session):
    _scope(session, WS, TENANT, SUB)
    _scope(session, OTHER_WS, OTHER_TENANT, OTHER_SUB)
    _nsg(session, 'nsg-open', [(100, 'Allow', 'Internet', '22', 'Tcp'), (110, 'Allow', '*', '443', 'Tcp')])
    _nsg(session, 'nsg-ssh', [(100, 'Allow', 'Internet', '22', 'Tcp')])
    _nsg(session, 'nsg-rfc1918', [(100, 'Allow', '10.0.0.0/8', '*', '*')])
    _nsg(session, 'nsg-deny22', [(100, 'Deny', 'Internet', '22', 'Tcp'), (200, 'Allow', 'Internet', '*', '*')])
    _nsg(session, 'nsg-closed', [(4000, 'Deny', '*', '*', '*')])
    _nsg(session, 'nsg-app', [(100, 'Allow', 'Internet', '8080', 'Tcp')])
    network.load_networks(session, SUB, [{'id': arm('virtualNetworks', VNET), 'name': VNET}], TAG)
    plain = _subnet(session, 'plain')
    deny22 = _subnet(session, 'deny22', nsg='nsg-deny22')
    closed = _subnet(session, 'closed', nsg='nsg-closed')
    nva = _subnet(session, 'nva', udr_hop='VirtualAppliance')

    ubuntu = ('0001-com-ubuntu-server-jammy', '22_04-lts')
    _vm(session, 'open', _nic(session, 'open', plain, 'nsg-open', '20.1.1.7'), *ubuntu)
    _vm(session, 'rfc1918', _nic(session, 'rfc1918', plain, 'nsg-rfc1918', '20.2.2.2'))
    # No NSG anywhere: a Standard SKU public IP is closed by default, a Basic one is open.
    _vm(session, 'std-no-nsg', _nic(session, 'std-no-nsg', plain, None, '20.6.6.6', sku='Standard'))
    _vm(session, 'basic-no-nsg', _nic(session, 'basic-no-nsg', plain, None, '20.7.7.7', sku='Basic'))
    _vm(session, 'subnet-deny22', _nic(session, 'subnet-deny22', deny22, None, '20.3.3.3'))
    _vm(session, 'nic-allow-subnet-deny', _nic(session, 'nic-allow-subnet-deny', closed, 'nsg-open', '20.4.4.4'))
    _vm(session, 'nva', _nic(session, 'nva', nva, 'nsg-open', '20.5.5.5'))
    app_nic = _nic(session, 'app', plain, 'nsg-app')
    _vm(session, 'app', app_nic)
    _load_balancer(session, app_nic)
    _paas(session)
    # Stale edge from a previous run must disappear.
    _run(
        session,
        "MATCH (vm:AzureVirtualMachine{id: 'vm-rfc1918'}), (c:AzureCosmosDBAccount{id: 'cosmos-filtered'}) "
        "MERGE (vm)-[e:CAN_NETWORK_REACH]->(c) SET e.lastupdated = 1",
    )
    # A node in another workspace must stay untouched.
    _run(
        session,
        "MATCH (s:AzureSubscription{id: $other}) MERGE (s)-[:RESOURCE]->(:AzureNetworkInterface{id: 'nic-other'})",
        other=OTHER_SUB,
    )


def _props(session, label, node_id):
    return session.run(f"MATCH (n:{label}{{id: $id}}) RETURN properties(n) AS p", id=node_id).single()["p"]


def test_azure_exposure_layers_end_to_end(neo4j_session):
    _build(neo4j_session)
    exposure_layers.run(neo4j_session, PARAMS)
    lb_id = arm('loadBalancers', 'lb1')

    def reach(label, node_id):
        p = _props(neo4j_session, label, node_id)
        return p['internet_reachable'], p['internet_reachable_ports'], p['internet_reachable_via'], p['public_reasons']

    # L1 + L2
    vm = 'AzureVirtualMachine'
    assert reach(vm, 'vm-open') == (True, ['tcp:22-22', 'tcp:443-443'], ['direct_ipv4'], ['public_ip'])
    assert reach(vm, 'vm-rfc1918') == (False, [], [], ['public_ip'])  # scenario 1
    assert reach(vm, 'vm-std-no-nsg') == (False, [], [], ['public_ip'])
    assert reach(vm, 'vm-basic-no-nsg')[:2] == (True, ['tcp:0-65535', 'udp:0-65535'])
    assert reach(vm, 'vm-subnet-deny22')[:2] == (True, ['tcp:0-21', 'tcp:23-65535', 'udp:0-65535'])
    assert reach(vm, 'vm-nic-allow-subnet-deny')[0] is False
    assert reach(vm, 'vm-nva') == (False, [], ['unknown:udr_default_route_virtualappliance'], ['public_ip'])  # 9
    assert reach(vm, 'vm-app') == (True, ['tcp:8080-8080'], [f'lb:{lb_id}'], [])  # scenario 4
    assert reach('AzureNetworkInterface', arm('networkInterfaces', 'open'))[:2] == (True, ['tcp:22-22', 'tcp:443-443'])
    assert reach('AzureNetworkLoadBalancer', lb_id) == (True, ['tcp:443-443'], ['public_frontend'], ['public_frontend'])
    assert reach('AzureVirtualMachineScaleSet', 'vmss-pip')[:2] == (True, ['tcp:22-22'])
    assert reach('AzureStorageAccount', 'st-open') == (True, ['tcp:443-443'], ['public_endpoint'], ['public_endpoint'])
    assert reach('AzureStorageAccount', 'st-firewalled') == (False, [], [], ['public_endpoint'])
    assert reach('AzureStorageBlobContainer', 'st-open/public')[0] is True
    assert reach('AzureSQLServer', 'sql-world')[:2] == (True, ['tcp:5432-5432'])
    assert reach('AzureSQLDatabase', 'sql-world/db1')[:2] == (True, ['tcp:5432-5432'])
    assert reach('AzureSQLServer', 'sql-office')[0] is False
    assert reach('AzureCosmosDBAccount', 'cosmos-open')[0] is True
    assert reach('AzureCosmosDBAccount', 'cosmos-filtered')[0] is False
    assert reach('AzureKeyVault', 'kv-off') == (False, [], [], [])
    assert reach('AzureCluster', 'aks-public')[:2] == (True, ['tcp:443-443'])
    assert reach('AzureCluster', 'aks-private') == (False, [], [], [])
    assert reach('AzureFunctionApp', 'fn-open')[:2] == (True, ['tcp:80-80', 'tcp:443-443'])
    assert reach('AzureContainerRegistry', 'acr-anon')[0] is True

    # L3
    def auth(label, node_id):
        p = _props(neo4j_session, label, node_id)
        return p['access_auth'], p['access_auth_reasons']

    assert auth('AzureStorageBlobContainer', 'st-open/public') == ('none', ['anonymous_container_access'])
    assert auth('AzureStorageBlobContainer', 'st-open/private')[0] == 'required'
    assert auth('AzureStorageAccount', 'st-open') == ('none', ['anonymous_blob_container'])
    assert auth('AzureSQLServer', 'sql-world') == ('required', ['entra_id_only'])
    assert auth('AzureSQLDatabase', 'sql-world/db1') == ('required', ['entra_id_only'])
    assert auth('AzureCosmosDBAccount', 'cosmos-filtered') == ('required', ['entra_id_only'])
    assert auth('AzureContainerRegistry', 'acr-anon') == ('none', ['anonymous_pull'])
    assert auth('AzureCluster', 'aks-public') == ('required', ['kubernetes_auth'])
    assert auth(vm, 'vm-open')[0] == 'unknown'

    # L4
    def software(label, node_id):
        p = _props(neo4j_session, label, node_id)
        return p['software_identity'], p.get('software_identity_source')

    assert software(vm, 'vm-open') == (['ubuntu@22.04'], 'image_name')
    assert software(vm, 'vm-app') == ([], None)
    assert software('AzureCluster', 'aks-public') == (['kubernetes@1.29.4'], 'managed_config')
    assert software('AzureSQLServer', 'sql-world') == (['postgres@15'], 'managed_config')
    assert software('AzureFunctionApp', 'fn-open') == (['python@3.11'], 'managed_config')

    # L5
    edges = {
        (r['src'], r['dst']): (r['via'], r['ports']) for r in neo4j_session.run(
            "MATCH (vm:AzureVirtualMachine)-[e:CAN_NETWORK_REACH]->(d) "
            "RETURN vm.id AS src, d.id AS dst, e.via AS via, e.ports AS ports",
        )
    }
    assert edges[('vm-open', 'sql-office')] == ('firewall_ip_rule', ['tcp:1433-1433'])
    assert edges[('vm-app', 'sql-world')] == ('public_endpoint', ['tcp:5432-5432'])
    assert ('vm-rfc1918', 'sql-office') not in edges
    assert ('vm-rfc1918', 'cosmos-filtered') not in edges  # stale edge removed

    # Other workspace untouched.
    assert 'internet_reachable' not in _props(neo4j_session, 'AzureNetworkInterface', 'nic-other')


def test_load_balancer_rule_cleanup(neo4j_session):
    _scope(neo4j_session, 'ws-lbr', 'tenant-lbr', 'sub-lbr')
    lb_id = '/subscriptions/sub-lbr/resourceGroups/rg/providers/Microsoft.Network/loadBalancers/lb'
    lb = {'id': lb_id, 'name': 'lb', 'load_balancing_rules': [{'id': f'{lb_id}/loadBalancingRules/old'}]}
    lb['rules'] = network._load_balancer_rules(lb)
    network.load_load_balancers(neo4j_session, 'sub-lbr', [lb], 1)
    network.load_load_balancer_rules(neo4j_session, [lb], 1)
    params = {
        'UPDATE_TAG': 2, 'WORKSPACE_ID': 'ws-lbr', 'AZURE_TENANT_ID': 'tenant-lbr', 'AZURE_SUBSCRIPTION_ID': 'sub-lbr',
        'LIMIT_SIZE': 100,
    }
    run_cleanup_job('azure_import_network_load_balancer_rules_cleanup.json', neo4j_session, params)
    count = "MATCH (r:AzureLoadBalancerRule) WHERE r.id STARTS WITH $lb RETURN count(r) AS c"
    assert neo4j_session.run(count, lb=lb_id).single()['c'] == 0
