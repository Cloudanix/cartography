"""
Scenario tests for the Azure NSG / VM / NIC / subnet exposure jobs, run for real
on Neo4j. Each scenario gets its own id prefix because the module fixture
shares one graph.
"""
from cartography.util import run_analysis_job

SUB = 'exp-sub'
TENANT = 'exp-tenant'
WORKSPACE = 'exp-ws'
PARAMS = {
    'UPDATE_TAG': 1, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
INBOUND_ANY = {'access': 'Allow', 'direction': 'Inbound', 'source_address_prefix': '*', 'protocol': 'Tcp'}


def _scope(session):
    session.run(
        "MERGE (w:CloudanixWorkspace{id: $ws}) MERGE (t:AzureTenant{id: $tenant}) "
        "MERGE (s:AzureSubscription{id: $sub}) MERGE (w)-[:OWNER]->(t) MERGE (t)-[:RESOURCE]->(s)",
        ws=WORKSPACE, tenant=TENANT, sub=SUB,
    )


def _nsg(session, nsg_id, rules):
    session.run(
        "MATCH (s:AzureSubscription{id: $sub}) MERGE (g:AzureNetworkSecurityGroup{id: $id}) "
        "SET g.name = $id MERGE (s)-[:RESOURCE]->(g)",
        sub=SUB, id=nsg_id,
    )
    for i, rule in enumerate(rules):
        session.run(
            "MATCH (g:AzureNetworkSecurityGroup{id: $nsg}) MERGE (r:AzureNetworkSecurityRule{id: $id}) "
            "SET r += $props MERGE (g)-[:CONTAIN]->(r)",
            nsg=nsg_id, id=f'{nsg_id}/rule{i}', props=rule,
        )


def _subnet(session, subnet_id, name='default', nsg_id=None):
    session.run(
        "MATCH (s:AzureSubscription{id: $sub}) MERGE (v:AzureNetwork{id: $vnet}) MERGE (s)-[:RESOURCE]->(v) "
        "MERGE (n:AzureNetworkSubnet{id: $id}) SET n.name = $name MERGE (v)-[:CONTAIN]->(n)",
        sub=SUB, vnet=f'{subnet_id}-vnet', id=subnet_id, name=name,
    )
    if nsg_id:
        session.run(
            "MATCH (n:AzureNetworkSubnet{id: $id}), (g:AzureNetworkSecurityGroup{id: $nsg}) "
            "MERGE (n)-[:MEMBER_NETWORK_SECURITY_GROUP]->(g)",
            id=subnet_id, nsg=nsg_id,
        )


def _nic(session, nic_id, nsg_id=None, subnet_id=None, public_ip=False):
    session.run(
        "MATCH (s:AzureSubscription{id: $sub}) MERGE (n:AzureNetworkInterface{id: $id}) MERGE (s)-[:RESOURCE]->(n)",
        sub=SUB, id=nic_id,
    )
    if nsg_id:
        session.run(
            "MATCH (n:AzureNetworkInterface{id: $id}), (g:AzureNetworkSecurityGroup{id: $nsg}) "
            "MERGE (n)-[:MEMBER_NETWORK_SECURITY_GROUP]->(g)",
            id=nic_id, nsg=nsg_id,
        )
    if subnet_id:
        session.run(
            "MATCH (n:AzureNetworkInterface{id: $id}), (s:AzureNetworkSubnet{id: $subnet}) MERGE (n)-[:SUBNET]->(s)",
            id=nic_id, subnet=subnet_id,
        )
    if public_ip:
        session.run(
            "MATCH (n:AzureNetworkInterface{id: $id}) MERGE (p:AzurePublicIPAddress{id: $pip}) "
            "MERGE (n)-[:MEMBER_PUBLIC_IP_ADDRESS]->(p)",
            id=nic_id, pip=f'{nic_id}-pip',
        )


def _vm(session, vm_id, nic_id):
    session.run(
        "MATCH (s:AzureSubscription{id: $sub}), (n:AzureNetworkInterface{id: $nic}) "
        "MERGE (v:AzureVirtualMachine{id: $id}) SET v.power_state = 'running' "
        "MERGE (s)-[:RESOURCE]->(v) MERGE (v)-[:MEMBER_NETWORK_INTERFACE]->(n)",
        sub=SUB, id=vm_id, nic=nic_id,
    )


def _exposed(session, label, prefix):
    rows = session.run(
        f"MATCH (n:{label}) WHERE n.id STARTS WITH $prefix AND n.exposed_internet = true "
        "RETURN n.id AS id, n.exposed_internet_type AS types",
        prefix=prefix,
    )
    return {r['id']: sorted(r['types']) for r in rows}


def test_nsg_exposure_needs_inbound_internet_source(neo4j_session):
    _scope(neo4j_session)
    _nsg(neo4j_session, 'nsg-ssh', [{**INBOUND_ANY, 'destination_port_range': '22'}])
    _nsg(neo4j_session, 'nsg-outbound', [{**INBOUND_ANY, 'direction': 'Outbound', 'destination_port_range': '22'}])
    _nsg(
        neo4j_session, 'nsg-corp-range',
        [{**INBOUND_ANY, 'source_address_prefix': '10.0.0.0/8', 'destination_port_range': '0-65535'}],
    )
    _nsg(
        neo4j_session, 'nsg-prefixes',
        [{
            **INBOUND_ANY, 'source_address_prefix': None, 'source_address_prefixes': ['10.1.0.0/16', 'Internet'],
            'destination_port_range': '443',
        }],
    )
    _nsg(neo4j_session, 'nsg-deny', [{**INBOUND_ANY, 'access': 'Deny', 'destination_port_range': '22'}])
    _nsg(neo4j_session, 'nsg-icmp', [{**INBOUND_ANY, 'protocol': 'Icmp', 'source_address_prefix': 'Internet'}])

    run_analysis_job('azure_network_security_group_asset_exposure.json', neo4j_session, PARAMS)

    assert _exposed(neo4j_session, 'AzureNetworkSecurityGroup', 'nsg-') == {
        'nsg-ssh': ['direct_ipv4', 'public_ssh'],
        'nsg-prefixes': ['direct_ipv4'],
        'nsg-icmp': ['direct_ipv4', 'public_icmp'],
    }


def test_vm_exposure_ignores_egress_route_and_bastion(neo4j_session):
    _scope(neo4j_session)
    _nsg(neo4j_session, 'vmx-nsg-out', [{**INBOUND_ANY, 'direction': 'Outbound'}])
    _nsg(neo4j_session, 'vmx-nsg-in', [{**INBOUND_ANY, 'destination_port_range': '22'}])

    # Private VM in a subnet with a 0.0.0.0/0 -> Internet route (egress only).
    _subnet(neo4j_session, 'vmx-subnet-route')
    neo4j_session.run(
        "MATCH (s:AzureNetworkSubnet{id: 'vmx-subnet-route'}) MERGE (rt:AzureRouteTable{id: 'vmx-rt'}) "
        "MERGE (r:AzureNetworkRoute{id: 'vmx-route'}) SET r.next_hop_type = 'Internet', r.address_prefix = '0.0.0.0/0' "
        "MERGE (s)-[:CONTAIN]->(rt) MERGE (rt)-[:CONTAIN]->(r)",
    )
    _nic(neo4j_session, 'vmx-nic-route', subnet_id='vmx-subnet-route')
    _vm(neo4j_session, 'vmx-route', 'vmx-nic-route')

    # Private VM in a VNet that has a Bastion host with a public IP.
    _subnet(neo4j_session, 'vmx-subnet-bastion', name='AzureBastionSubnet')
    _subnet(neo4j_session, 'vmx-subnet-app')
    neo4j_session.run(
        "MATCH (v:AzureNetwork{id: 'vmx-subnet-bastion-vnet'}), (s:AzureNetworkSubnet{id: 'vmx-subnet-app'}), "
        "(b:AzureNetworkSubnet{id: 'vmx-subnet-bastion'}) "
        "MERGE (v)-[:CONTAIN]->(s) MERGE (h:AzureNetworkBastionHost{id: 'vmx-bastion'}) "
        "MERGE (p:AzurePublicIPAddress{id: 'vmx-bastion-pip'}) MERGE (b)-[:CONTAIN]->(h) "
        "MERGE (h)-[:MEMBER_PUBLIC_IP_ADDRESS]->(p)",
    )
    _nic(neo4j_session, 'vmx-nic-bastion', subnet_id='vmx-subnet-app')
    _vm(neo4j_session, 'vmx-bastion-vm', 'vmx-nic-bastion')

    _nic(neo4j_session, 'vmx-nic-out', nsg_id='vmx-nsg-out')
    _vm(neo4j_session, 'vmx-outbound', 'vmx-nic-out')
    _nic(neo4j_session, 'vmx-nic-in', nsg_id='vmx-nsg-in')
    _vm(neo4j_session, 'vmx-inbound', 'vmx-nic-in')

    run_analysis_job('azure_vm_asset_exposure.json', neo4j_session, PARAMS)

    assert _exposed(neo4j_session, 'AzureVirtualMachine', 'vmx-') == {
        'vmx-inbound': ['direct_ipv4', 'public_ssh'],
    }


def test_nic_exposure_needs_inbound_internet_source(neo4j_session):
    _scope(neo4j_session)
    _nsg(neo4j_session, 'nicx-nsg-out', [{**INBOUND_ANY, 'direction': 'Outbound'}])
    _nsg(neo4j_session, 'nicx-nsg-corp', [{**INBOUND_ANY, 'source_address_prefix': '10.0.0.0/8'}])
    _nsg(neo4j_session, 'nicx-nsg-in', [{**INBOUND_ANY, 'source_address_prefix': 'Internet'}])
    _subnet(neo4j_session, 'nicx-subnet-in', nsg_id='nicx-nsg-in')
    _nic(neo4j_session, 'nicx-out', nsg_id='nicx-nsg-out')
    _nic(neo4j_session, 'nicx-corp', nsg_id='nicx-nsg-corp')
    _nic(neo4j_session, 'nicx-via-subnet', subnet_id='nicx-subnet-in')

    run_analysis_job('azure_network_interface_asset_exposure.json', neo4j_session, PARAMS)

    assert _exposed(neo4j_session, 'AzureNetworkInterface', 'nicx-') == {
        'nicx-via-subnet': ['public_interface_subnet'],
    }


def test_subnet_exposure(neo4j_session):
    _scope(neo4j_session)
    _nsg(neo4j_session, 'subx-nsg-out', [{**INBOUND_ANY, 'direction': 'Outbound'}])
    _nsg(neo4j_session, 'subx-nsg-in', [{**INBOUND_ANY, 'source_address_prefix': 'Internet'}])
    _subnet(neo4j_session, 'subx-gateway', name='GatewaySubnet')
    _subnet(neo4j_session, 'subx-firewall', name='AzureFirewallSubnet')
    _subnet(neo4j_session, 'subx-private')
    _nic(neo4j_session, 'subx-private-nic', subnet_id='subx-private')
    _subnet(neo4j_session, 'subx-public-nic')
    _nic(neo4j_session, 'subx-public-nic-nic', subnet_id='subx-public-nic', public_ip=True)
    _subnet(neo4j_session, 'subx-outbound', nsg_id='subx-nsg-out')
    _subnet(neo4j_session, 'subx-inbound', nsg_id='subx-nsg-in')

    run_analysis_job('azure_network_subnet_asset_exposure.json', neo4j_session, PARAMS)

    assert _exposed(neo4j_session, 'AzureNetworkSubnet', 'subx-') == {
        'subx-public-nic': ['no_nsg_attached'],
        'subx-inbound': ['internet_exposed_rule'],
    }
