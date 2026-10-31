"""
Scenario test for azure_vmss_asset_exposure.json, run for real on Neo4j with
scale sets loaded through compute.py and load balancers through network.py.
"""
from cartography.intel.azure import compute
from cartography.intel.azure import network
from cartography.util import run_analysis_job

SUB = 'vmssx-sub'
TENANT = 'vmssx-tenant'
WORKSPACE = 'vmssx-ws'
PARAMS = {
    'UPDATE_TAG': 2, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
RG = '/subscriptions/vmssx-sub/resourceGroups/rg/providers'
PUBLIC_LB = f'{RG}/Microsoft.Network/loadBalancers/public'
INTERNAL_LB = f'{RG}/Microsoft.Network/loadBalancers/internal'
LEGACY_LB = f'{RG}/Microsoft.Network/loadBalancers/legacy'
PIP = f'{RG}/Microsoft.Network/publicIPAddresses/lb-pip'


def _pool(lb, name):
    return f'{lb}/backendAddressPools/{name}'.lower()


def _lb(lb_id, inbound_pools, public):
    frontend = {'id': f'{lb_id}/frontendIPConfigurations/fe', 'name': 'fe'}
    if public:
        frontend['public_ip_address'] = {'id': PIP}
    return {
        'id': lb_id, 'name': lb_id.rsplit('/', 1)[-1], 'location': 'eastus',
        'frontend_ip_configurations': [frontend], 'inbound_backend_pool_ids': inbound_pools,
    }


def _scale_set(name, pools=(), nat_lbs=(), public_ip=False):
    return {
        'id': f'{RG}/Microsoft.Compute/virtualMachineScaleSets/{name}', 'name': name, 'location': 'eastus',
        'resource_group': 'rg', 'public_ip_per_instance': public_ip,
        'lb_backend_pool_ids': list(pools), 'lb_inbound_nat_lb_ids': [lb.lower() for lb in nat_lbs],
    }


def test_vmss_exposure(neo4j_session):
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(s:AzureSubscription{id: $sub}) MERGE (s)-[:RESOURCE]->(:AzurePublicIPAddress{id: $pip})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB, pip=PIP,
    )
    lbs = [
        _lb(PUBLIC_LB, [_pool(PUBLIC_LB, 'web')], public=True),
        _lb(INTERNAL_LB, [_pool(INTERNAL_LB, 'web')], public=False),
        # Synced before inbound pools were recorded: its rules are unknown.
        _lb(LEGACY_LB, None, public=True),
    ]
    network.load_load_balancers(neo4j_session, SUB, lbs, 1)
    network.load_frontend_ip_configurations(neo4j_session, lbs, 1)
    sets = [
        _scale_set('instance-pip', public_ip=True),
        _scale_set('web', pools=[_pool(PUBLIC_LB, 'web')]),
        _scale_set('egress-only', pools=[_pool(PUBLIC_LB, 'egress')]),
        _scale_set('nat-pool', nat_lbs=[PUBLIC_LB]),
        _scale_set('internal', pools=[_pool(INTERNAL_LB, 'web')]),
        _scale_set('legacy-lb', pools=[_pool(LEGACY_LB, 'web')]),
        _scale_set('bare'),
        _scale_set('stale'),
    ]
    compute.load_vm_scale_sets(neo4j_session, SUB, sets, 1)
    neo4j_session.run(
        "MATCH (v:AzureVirtualMachineScaleSet{id: $id}) "
        "SET v.exposed_internet = true, v.exposed_internet_type = ['public_ip']",
        id=f'{RG}/Microsoft.Compute/virtualMachineScaleSets/stale',
    )

    run_analysis_job('azure_vmss_asset_exposure.json', neo4j_session, PARAMS)

    rows = neo4j_session.run(
        "MATCH (v:AzureVirtualMachineScaleSet) WHERE v.id STARTS WITH $rg "
        "RETURN v.name AS name, v.exposed_internet AS exposed, v.exposed_internet_type AS types, "
        "v.publicContext IS NOT NULL AS has_context",
        rg=RG,
    )
    actual = {r['name']: (r['exposed'], sorted(r['types'] or []), r['has_context']) for r in rows}
    assert actual == {
        'instance-pip': (True, ['public_ip'], True),
        'web': (True, ['public_load_balancer'], True),
        # A pool only used by outbound (SNAT) rules receives no inbound traffic.
        'egress-only': (None, [], False),
        'nat-pool': (True, ['public_load_balancer'], True),
        'internal': (None, [], False),
        'legacy-lb': (True, ['public_load_balancer'], True),
        'bare': (None, [], False),
        'stale': (None, [], False),
    }


def test_vmss_front_doors_update_on_resync(neo4j_session):
    scale_set = _scale_set('resync', public_ip=True)
    compute.load_vm_scale_sets(neo4j_session, SUB, [scale_set], 1)
    compute.load_vm_scale_sets(neo4j_session, SUB, [{**scale_set, 'public_ip_per_instance': False}], 2)

    row = neo4j_session.run(
        "MATCH (v:AzureVirtualMachineScaleSet{id: $id}) RETURN v.public_ip_per_instance AS pip",
        id=scale_set['id'],
    ).single()
    assert row['pip'] is False
