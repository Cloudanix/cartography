"""
Network links stay inside the syncing subscription, or inside the customer's workspace where Azure lets a
resource reference another subscription (public IPs, load balancer / app gateway backends). AGENTS.md rule 7.
"""
from cartography.intel.azure import network
from cartography.intel.azure import network_gateways
from cartography.intel.azure import subscription
from cartography.intel.azure import tag
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import CUSTOMERS
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import RESOURCE_GROUP
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

TAG = UPDATE_TAG
WS_A, TENANT_A = CUSTOMERS[SUB_A]
# A second subscription of customer A (same workspace and tenant).
SUB_A2 = 'aaaaaaaa-0000-0000-0000-0000000000a2'
NIC, NSG, PIP = 'AzureNetworkInterface', 'AzureNetworkSecurityGroup', 'AzurePublicIPAddress'
SUBNET, IPC = 'AzureNetworkSubnet', 'AzureNetworkInterfaceIPConfiguration'
LB = 'AzureNetworkLoadBalancer'
NSG_REL, PIP_REL = 'MEMBER_NETWORK_SECURITY_GROUP', 'MEMBER_PUBLIC_IP_ADDRESS'


def ids(sub, suffix=''):
    """The ids of one subscription's network resources (suffix tells apart a second set)."""
    vnet = arm_id(sub, f'Microsoft.Network/virtualNetworks/vnet{suffix}')
    nsg = arm_id(sub, f'Microsoft.Network/networkSecurityGroups/nsg{suffix}')
    nic = arm_id(sub, f'Microsoft.Network/networkInterfaces/nic{suffix}')
    rt = arm_id(sub, f'Microsoft.Network/routeTables/rt{suffix}')
    return {
        'vnet': vnet, 'subnet': f'{vnet}/subnets/default', 'usage': f'{vnet}/usages/u',
        'nsg': nsg, 'rule': f'{nsg}/securityRules/allow', 'rt': rt, 'route': f'{rt}/routes/r',
        'nic': nic, 'ipc': f'{nic}/ipConfigurations/ipconfig1',
        'pip': arm_id(sub, f'Microsoft.Network/publicIPAddresses/pip{suffix}'),
        'lb': arm_id(sub, f'Microsoft.Network/loadBalancers/lb{suffix}'),
        'nat': arm_id(sub, f'Microsoft.Network/natGateways/nat{suffix}'),
        'bastion': arm_id(sub, f'Microsoft.Network/bastionHosts/bastion{suffix}'),
        'agw': arm_id(sub, f'Microsoft.Network/applicationGateways/agw{suffix}'),
        'fw': arm_id(sub, f'Microsoft.Network/azureFirewalls/fw{suffix}'),
    }


A, A2, B = ids(SUB_A), ids(SUB_A2), ids(SUB_B)


def _seed_network(neo4j_session, sub):
    """The graph the network loaders write for `sub`, with every node under its subscription."""
    neo4j_session.run(
        """
        MATCH (s:AzureSubscription{id: $sub})
        MERGE (s)-[:RESOURCE]->(:AzureNetwork{id: $n.vnet})-[:CONTAIN]->(:AzureNetworkSubnet{id: $n.subnet})
        MERGE (s)-[:RESOURCE]->(:AzureNetworkSecurityGroup{id: $n.nsg})-[:CONTAIN]->
            (:AzureNetworkSecurityRule{id: $n.rule})
        MERGE (s)-[:RESOURCE]->(:AzureNetworkInterface{id: $n.nic})-[:CONTAINS]->
            (:AzureNetworkInterfaceIPConfiguration{id: $n.ipc})
        MERGE (s)-[:RESOURCE]->(:AzureRouteTable{id: $n.rt})
        MERGE (s)-[:RESOURCE]->(:AzurePublicIPAddress{id: $n.pip})
        MERGE (s)-[:RESOURCE]->(:AzureNetworkLoadBalancer{id: $n.lb})
        MERGE (s)-[:RESOURCE]->(:AzureNatGateway{id: $n.nat})
        MERGE (s)-[:RESOURCE]->(:AzureNetworkBastionHost{id: $n.bastion})
        """,
        sub=sub, n=ids(sub),
    ).consume()


def _seed(neo4j_session):
    seed_customers(neo4j_session)
    subscription.load_azure_subscriptions(
        neo4j_session, TENANT_A, [{'id': f'/subscriptions/{SUB_A2}', 'subscriptionId': SUB_A2}], TAG,
    )
    tag.load_resource_groups(neo4j_session, SUB_A2, [{'id': rg_id(SUB_A2), 'name': RESOURCE_GROUP}], TAG)
    _seed_network(neo4j_session, SUB_A2)
    _seed_network(neo4j_session, SUB_B)
    _load_network(neo4j_session, A)


def _load_network(neo4j_session, n):
    """VNet, subnet, NSG, route table, NIC, public IP, load balancer, NAT gateway and bastion host, synced as SUB_A."""
    network.load_network_security_groups(neo4j_session, SUB_A, [{'id': n['nsg']}], TAG)
    network.load_networks(neo4j_session, SUB_A, [{'id': n['vnet']}], TAG)
    subnet = {'id': n['subnet'], 'network_id': n['vnet'], 'network_security_group_id': n['nsg']}
    network.load_networks_subnets(neo4j_session, [subnet], SUB_A, TAG)
    network.load_network_routetables(neo4j_session, SUB_A, [{'id': n['rt']}], TAG)
    network.load_network_routes(neo4j_session, SUB_A, [{'id': n['route'], 'routetable_id': n['rt']}], TAG)
    network.load_network_security_rules(neo4j_session, SUB_A, [{'id': n['rule'], 'security_group_id': n['nsg']}], TAG)
    network.load_usages(neo4j_session, SUB_A, [{'id': n['usage'], 'network_id': n['vnet']}], TAG)
    network.load_network_interfaces(neo4j_session, SUB_A, [{'id': n['nic']}], TAG)
    nic_ipcs = {'id': n['nic'], 'ip_configurations': [{'id': n['ipc']}]}
    network.load_ip_configurations(neo4j_session, SUB_A, [nic_ipcs], TAG)
    network.load_public_ip_addresses(neo4j_session, SUB_A, [{'id': n['pip']}], TAG)
    network.load_load_balancers(neo4j_session, SUB_A, [{'id': n['lb']}], TAG)
    network.load_network_nat_gateway(neo4j_session, SUB_A, [{'id': n['nat']}], TAG)
    network.load_network_bastion_hosts(neo4j_session, SUB_A, [{'id': n['bastion']}], TAG)


def test_resource_groups_come_from_the_syncing_subscription(neo4j_session):
    _seed(neo4j_session)
    # Ids the API returned while syncing SUB_A that name SUB_B: the subscription in an id is not an anchor.
    foreign = ids(SUB_B, suffix='-x')
    _load_network(neo4j_session, foreign)
    labels = {
        'vnet': 'AzureNetwork', 'subnet': SUBNET, 'usage': 'AzureNetworkUsage', 'nsg': NSG,
        'rule': 'AzureNetworkSecurityRule', 'rt': 'AzureRouteTable', 'route': 'AzureNetworkRoute', 'nic': NIC,
        'lb': LB, 'nat': 'AzureNatGateway',
    }
    for n in (A, foreign):
        for key, label in labels.items():
            assert resource_group_of(neo4j_session, label, n[key]) == {rg_id(SUB_A)}, (label, n[key])


def test_same_subscription_links_never_reach_another_subscription(neo4j_session):
    _seed(neo4j_session)

    def linked(label, node_id, rel, end):
        return linked_ids(neo4j_session, label, node_id, rel, end)

    # A subnet whose VNet and NSG ids name the other customer's.
    other = f"{A['vnet']}/subnets/other"
    subnet = {'id': other, 'network_id': B['vnet'], 'network_security_group_id': B['nsg']}
    network.load_networks_subnets(neo4j_session, [subnet], SUB_A, TAG)
    assert linked(SUBNET, A['subnet'], 'CONTAIN', 'AzureNetwork') == {A['vnet']}
    assert linked(SUBNET, other, 'CONTAIN', 'AzureNetwork') == set()
    assert linked(SUBNET, A['subnet'], NSG_REL, NSG) == {A['nsg']}
    assert linked(SUBNET, other, NSG_REL, NSG) == set()

    # Route table / bastion / NAT gateway -> subnet, own and the other customer's parent looked up by id.
    subnets = [{'id': A['subnet']}, {'id': B['subnet']}, {'id': A2['subnet']}]
    tables = [{'id': A['rt'], 'subnets': subnets}, {'id': B['rt'], 'subnets': subnets}]
    network.attach_network_routetables_to_subnet(neo4j_session, SUB_A, tables, TAG)
    bastions = [{'id': A['bastion'], 'subnets': subnets}, {'id': B['bastion'], 'subnets': subnets}]
    network.attach_network_bastion_hosts_to_subnet(neo4j_session, SUB_A, bastions, TAG)
    network.load_network_nat_gateway_subnet(neo4j_session, SUB_A, A['nat'], subnets, TAG)
    network.load_network_nat_gateway_subnet(neo4j_session, SUB_A, B['nat'], subnets, TAG)
    for label, key, rel in [
        ('AzureRouteTable', 'rt', 'CONTAIN'), ('AzureNetworkBastionHost', 'bastion', 'CONTAIN'),
        ('AzureNatGateway', 'nat', 'ATTACHED_TO'),
    ]:
        assert linked(label, A[key], rel, SUBNET) == {A['subnet']}, label
        assert linked(label, B[key], rel, SUBNET) == set(), label

    # Children loaded under SUB_A whose parent id is the other customer's: no edge into that parent.
    network.load_network_routes(neo4j_session, SUB_A, [{'id': f"{B['rt']}/routes/x", 'routetable_id': B['rt']}], TAG)
    assert linked('AzureRouteTable', B['rt'], 'CONTAIN', 'AzureNetworkRoute') == set()
    prefix = '198.51.100.0/24'
    rules = [
        {'id': f"{A['nsg']}/securityRules/own", 'security_group_id': A['nsg'], 'source_address_prefix': prefix},
        {'id': f"{B['nsg']}/securityRules/x", 'security_group_id': B['nsg'], 'source_address_prefix': prefix},
    ]
    network.load_network_security_rules(neo4j_session, SUB_A, rules, TAG)
    assert linked(NSG, B['nsg'], 'CONTAIN', 'AzureNetworkSecurityRule') == {B['rule']}
    ranges = "MATCH (:IpRange)-[:MEMBER_OF_NETWORK_SECURITY_RULE]->(:AzureNetworkSecurityRule{id: $id}) RETURN count(*)"
    assert neo4j_session.run(ranges, id=rules[0]['id']).single()[0] == 1
    assert neo4j_session.run(ranges, id=rules[1]['id']).single()[0] == 0
    network.load_usages(neo4j_session, SUB_A, [{'id': f"{B['vnet']}/usages/x", 'network_id': B['vnet']}], TAG)
    assert linked('AzureNetwork', B['vnet'], 'CONTAIN', 'AzureNetworkUsage') == set()

    # NICs: NSG, ip configurations and subnets of the syncing subscription only.
    nic2 = f"{A['nic']}-2"
    nics = [
        {'id': A['nic'], 'network_security_group': {'id': A['nsg']}},
        {'id': nic2, 'network_security_group': {'id': B['nsg']}},
    ]
    network.load_network_interfaces(neo4j_session, SUB_A, nics, TAG)
    assert linked(NIC, A['nic'], NSG_REL, NSG) == {A['nsg']}
    assert linked(NIC, nic2, NSG_REL, NSG) == set()
    foreign_ipc = {'id': B['nic'], 'ip_configurations': [{'id': f"{B['nic']}/ipConfigurations/x"}]}
    network.load_ip_configurations(neo4j_session, SUB_A, [foreign_ipc], TAG)
    assert linked(NIC, B['nic'], 'CONTAINS', IPC) == {B['ipc']}
    nic_subnets = [{'id': A['nic'], 'subnet': [{'subnet_id': s['id']} for s in subnets]}]
    network.attach_subnet_to_network_interfaces(neo4j_session, SUB_A, nic_subnets, TAG)
    assert linked(NIC, A['nic'], 'SUBNET', SUBNET) == {A['subnet']}

    # Load balancer rules: never under the other customer's load balancer.
    network.load_load_balancer_rules(neo4j_session, SUB_A, [{'id': B['lb'], 'rules': [{'id': f"{B['lb']}/r"}]}], TAG)
    assert linked(LB, B['lb'], 'HAS', 'AzureLoadBalancerRule') == set()


def test_public_ips_and_backends_stay_in_the_workspace(neo4j_session):
    _seed(neo4j_session)

    def linked(label, node_id, rel, end):
        return linked_ids(neo4j_session, label, node_id, rel, end)

    pips = [{'public_ip_id': A['pip']}, {'public_ip_id': A2['pip']}, {'public_ip_id': B['pip']}]
    workspace_pips = {A['pip'], A2['pip']}
    attach = [
        (network.load_public_ip_network_interfaces_relationship, NIC, 'nic'),
        (network.attach_public_ip_to_bastion_host, 'AzureNetworkBastionHost', 'bastion'),
        (network.attach_public_ip_to_load_balancer, LB, 'lb'),
    ]
    for load, label, key in attach:
        load(neo4j_session, SUB_A, WS_A, A[key], pips, TAG)
        # ...and never from the other customer's NIC / bastion / load balancer.
        load(neo4j_session, SUB_A, WS_A, B[key], pips, TAG)
        assert linked(label, A[key], PIP_REL, PIP) == workspace_pips, label
        assert linked(label, B[key], PIP_REL, PIP) == set(), label

    # Load balancer frontends and backend pools.
    frontends = [
        {'id': f"{A['lb']}/frontendIPConfigurations/{i}", 'public_ip_address': {'id': p['public_ip_id']}}
        for i, p in enumerate(pips)
    ]
    pool = f"{A['lb']}/backendAddressPools/web"
    backends = [{'id': A['ipc']}, {'id': A2['ipc']}, {'id': B['ipc']}]
    lbs = [
        {
            'id': A['lb'], 'frontend_ip_configurations': frontends,
            'backend_address_pools': [{'id': pool, 'backend_ip_configurations': backends}],
        },
        {
            'id': B['lb'], 'frontend_ip_configurations': [{'id': f"{B['lb']}/frontendIPConfigurations/x"}],
            'backend_address_pools': [],
        },
    ]
    network.load_frontend_ip_configurations(neo4j_session, SUB_A, WS_A, lbs, TAG)
    network.load_backend_address_pools(neo4j_session, SUB_A, WS_A, lbs, TAG)
    fe_pips = neo4j_session.run(
        "MATCH (:AzureNetworkLoadBalancer{id: $lb})-[:HAS]->(:AzureLoadBalancerFrontendIPConfiguration)"
        "-[:MEMBER_PUBLIC_IP_ADDRESS]->(p) RETURN collect(p.id)", lb=A['lb'],
    ).single()[0]
    assert set(fe_pips) == workspace_pips
    assert linked(LB, B['lb'], 'HAS', 'AzureLoadBalancerFrontendIPConfiguration') == set()
    assert linked('AzureLoadBalancerBackendAddressPool', pool, 'HAS', IPC) == {A['ipc'], A2['ipc']}
    # A stale pool -> other customer's ip configuration edge (written before this change) must not become a NIC link.
    neo4j_session.run(
        "MATCH (p:AzureLoadBalancerBackendAddressPool{id: $pool}), (i:AzureNetworkInterfaceIPConfiguration{id: $ipc}) "
        "MERGE (p)-[:HAS]->(i)", pool=pool, ipc=B['ipc'],
    ).consume()
    network.create_relationship_between_network_interface_and_load_balancer(neo4j_session, SUB_A, WS_A, lbs, TAG)
    assert linked(LB, A['lb'], 'CONNECTED_TO', NIC) == {A['nic'], A2['nic']}


def test_gateways_and_firewalls_stay_in_the_workspace(neo4j_session):
    _seed(neo4j_session)
    links = {'subnet_ids': [A['subnet'], A2['subnet'], B['subnet']], 'public_ip_ids': [A['pip'], A2['pip'], B['pip']]}
    gateway = {'id': A['agw'], 'rules': [], 'backend_ip_configuration_ids': [A['ipc'], A2['ipc'], B['ipc']], **links}
    network_gateways.load_application_gateways(neo4j_session, SUB_A, WS_A, [gateway], TAG)
    network_gateways.load_firewalls(neo4j_session, SUB_A, WS_A, [{'id': A['fw'], 'rules': [], **links}], TAG)
    for label, key in [('AzureApplicationGateway', 'agw'), ('AzureFirewall', 'fw')]:
        # The gateway's subnet is in its own subscription's VNet; its public IPs may be in another of the customer's.
        assert linked_ids(neo4j_session, label, A[key], 'SUBNET', SUBNET) == {A['subnet']}, label
        assert linked_ids(neo4j_session, label, A[key], PIP_REL, PIP) == {A['pip'], A2['pip']}, label
    connected = linked_ids(neo4j_session, 'AzureApplicationGateway', A['agw'], 'CONNECTED_TO', NIC)
    assert connected == {A['nic'], A2['nic']}
