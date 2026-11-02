from cartography.intel.azure import redis
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import CUSTOMERS
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

# A second subscription of customer A (same tenant): a cache may sit in a VNet there.
SUB_A2 = 'aaaaaaaa-0000-0000-0000-0000000000a2'
CACHE_A = arm_id(SUB_A, 'Microsoft.Cache/Redis/cache')
CACHE_B = arm_id(SUB_B, 'Microsoft.Cache/Redis/cache')


def _vnet(sub):
    return arm_id(sub, 'Microsoft.Network/virtualNetworks/vnet')


def _subnet(sub):
    return f'{_vnet(sub)}/subnets/redis'


def _seed(neo4j_session):
    seed_customers(neo4j_session)
    neo4j_session.run(
        "MATCH (t:AzureTenant{id: $tenant}) MERGE (t)-[:RESOURCE]->(:AzureSubscription{id: $sub})",
        tenant=CUSTOMERS[SUB_A][1], sub=SUB_A2,
    )
    for sub in (SUB_A, SUB_A2, SUB_B):
        seed_node(neo4j_session, sub, 'AzureNetwork', _vnet(sub))
        neo4j_session.run(
            "MATCH (v:AzureNetwork{id: $vnet}) MERGE (v)-[:CONTAIN]->(:AzureNetworkSubnet{id: $subnet})",
            vnet=_vnet(sub), subnet=_subnet(sub),
        )
    seed_node(neo4j_session, SUB_B, 'AzureRedisCache', CACHE_B)


def _cache(name, subnet_id):
    return {'id': arm_id(SUB_A, f'Microsoft.Cache/Redis/{name}'), 'name': name, 'subnet_id': subnet_id}


def test_redis_links_stay_in_the_syncing_customer(neo4j_session):
    _seed(neo4j_session)
    caches = [_cache('own', _subnet(SUB_A)), _cache('sibling', _subnet(SUB_A2)), _cache('foreign', _subnet(SUB_B))]

    redis.load_caches(neo4j_session, SUB_A, caches, UPDATE_TAG)
    redis.load_firewall_rules(
        neo4j_session, SUB_A,
        [
            {'id': f'{CACHE_A}/firewallRules/own', 'name': 'own', 'cache_id': caches[0]['id']},
            {'id': f'{CACHE_A}/firewallRules/x', 'name': 'x', 'cache_id': CACHE_B},
        ],
        UPDATE_TAG,
    )

    subnets = {c['name']: linked_ids(neo4j_session, 'AzureRedisCache', c['id'], 'SUBNET', 'AzureNetworkSubnet')
               for c in caches}
    # Own subscription and a sibling subscription of the same tenant link; another customer's subnet never does.
    assert subnets == {'own': {_subnet(SUB_A)}, 'sibling': {_subnet(SUB_A2)}, 'foreign': set()}
    assert linked_ids(neo4j_session, 'AzureRedisCache', caches[0]['id'], 'HAS', 'AzureRedisFirewallRule') == {
        f'{CACHE_A}/firewallRules/own',
    }
    assert linked_ids(neo4j_session, 'AzureRedisCache', CACHE_B, 'HAS', 'AzureRedisFirewallRule') == set()
