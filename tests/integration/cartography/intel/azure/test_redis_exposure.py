"""
Scenario test for azure_redis_asset_exposure.json, run for real on Neo4j with
caches and firewall rules loaded through the redis.py loaders.
"""
import json

from cartography.intel.azure import redis
from cartography.util import run_analysis_job

SUB = 'redisx-sub'
TENANT = 'redisx-tenant'
WORKSPACE = 'redisx-ws'
PARAMS = {
    'UPDATE_TAG': 2, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
PREFIX = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Cache/Redis/'
OTHER_PREFIX = '/subscriptions/redisx-other/resourceGroups/rg/providers/Microsoft.Cache/Redis/'
SUBNET_ID = f'/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vn/subnets/redis'


def _cache(name, access='Enabled', subnet_id=None, fetched=True, prefix=PREFIX, private_endpoints=0):
    return {
        'id': f'{prefix}{name}', 'name': name, 'location': 'eastus', 'resource_group': 'rg',
        'sku_name': 'Premium', 'public_network_access': access, 'subnet_id': subnet_id,
        'host_name': f'{name}.redis.cache.windows.net', 'port': 6379, 'ssl_port': 6380,
        'enable_non_ssl_port': False, 'minimum_tls_version': '1.2', 'redis_version': '6.0',
        'private_endpoint_connection_count': private_endpoints, 'firewall_rules_fetched': fetched,
    }


def _rule(cache, name, start, end):
    rule = {
        'id': f"{cache['id']}/firewallRules/{name}", 'name': name, 'cache_id': cache['id'],
        'start_ip_address': start, 'end_ip_address': end,
    }
    rule['address_count'] = redis._firewall_rule_address_count(rule)
    return rule


def _exposure(neo4j_session, prefix):
    rows = neo4j_session.run(
        "MATCH (c:AzureRedisCache) WHERE c.id STARTS WITH $prefix "
        "RETURN c.name AS name, c.exposed_internet AS exposed, c.exposed_internet_type AS types",
        prefix=prefix,
    )
    return {r['name']: (r['exposed'], sorted(r['types'] or [])) for r in rows}


def test_redis_cache_exposure(neo4j_session):
    neo4j_session.run(
        "MERGE (ws:CloudanixWorkspace{id: $ws})-[:OWNER]->(t:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(:AzureSubscription{id: $sub}) "
        "MERGE (:CloudanixWorkspace{id: 'redisx-other-ws'})-[:OWNER]->(:AzureTenant{id: 'redisx-other-tenant'})"
        "-[:RESOURCE]->(:AzureSubscription{id: 'redisx-other'})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB,
    )
    closed = _cache('closed', access='Disabled')
    closed_open_rule = _cache('closed-open-rule', access='Disabled')
    closed_unread = _cache('closed-unread', access='Disabled', fetched=False)
    injected = _cache('injected', subnet_id=SUBNET_ID)
    injected_unread = _cache('injected-unread', access=None, subnet_id=SUBNET_ID, fetched=False)
    no_rules = _cache('no-rules')
    unknown_access = _cache('unknown-access', access=None)
    private_endpoint = _cache('private-endpoint', private_endpoints=1)
    open_all = _cache('open-all')
    wide = _cache('wide')
    slash8 = _cache('slash8')
    office = _cache('office')
    zero = _cache('zero')
    garbled = _cache('garbled')
    unread = _cache('unread', fetched=False)
    stale = _cache('stale', access='Disabled')
    other_ws = _cache('other-ws', prefix=OTHER_PREFIX)
    caches = [
        closed, closed_open_rule, closed_unread, injected, injected_unread, no_rules, unknown_access,
        private_endpoint, open_all, wide, slash8, office, zero, garbled, unread, stale,
    ]
    redis.load_caches(neo4j_session, SUB, caches, 2)
    redis.load_caches(neo4j_session, 'redisx-other', [other_ws], 2)
    redis.load_firewall_rules(
        neo4j_session,
        [
            _rule(closed_open_rule, 'all', '0.0.0.0', '255.255.255.255'),
            _rule(injected, 'all', '0.0.0.0', '255.255.255.255'),
            _rule(open_all, 'all', '0.0.0.0', '255.255.255.255'),
            _rule(open_all, 'office', '203.0.113.10', '203.0.113.10'),
            _rule(wide, 'wide', '1.0.0.0', '3.255.255.255'),
            _rule(slash8, 'corp', '10.0.0.0', '10.255.255.255'),
            _rule(office, 'office', '203.0.113.10', '203.0.113.20'),
            _rule(zero, 'zero', '0.0.0.0', '0.0.0.0'),
            _rule(garbled, 'bad', 'not-an-ip', '1.1.1.1'),
        ],
        2,
    )
    # Left over from an earlier run: the job must reset it before evaluating.
    neo4j_session.run(
        "MATCH (c:AzureRedisCache{id: $id}) SET c.exposed_internet = true, "
        "c.exposed_internet_type = ['public_network_no_firewall'], c.publicContext = '[]'",
        id=stale['id'],
    )

    run_analysis_job('azure_redis_asset_exposure.json', neo4j_session, PARAMS)

    assert _exposure(neo4j_session, PREFIX) == {
        'closed': (None, []),
        'closed-open-rule': (None, []),
        'closed-unread': (None, []),
        'injected': (None, []),
        'injected-unread': (None, []),
        'no-rules': (True, ['public_network_no_firewall']),
        'unknown-access': (True, ['public_network_no_firewall']),
        'private-endpoint': (True, ['public_network_no_firewall']),
        'open-all': (True, ['unrestricted_firewall']),
        'wide': (True, ['unrestricted_firewall']),
        'slash8': (None, []),
        'office': (None, []),
        'zero': (None, []),
        'garbled': (True, ['unrestricted_firewall']),
        'unread': (True, ['firewall_not_evaluated']),
        'stale': (None, []),
    }
    # A second run (next sync, nothing changed) gives the same answer, no duplicated types.
    before = _exposure(neo4j_session, PREFIX)
    run_analysis_job('azure_redis_asset_exposure.json', neo4j_session, PARAMS)
    assert _exposure(neo4j_session, PREFIX) == before
    # Another workspace's subscription is never touched.
    assert _exposure(neo4j_session, OTHER_PREFIX) == {'other-ws': (None, [])}

    [context] = json.loads(
        neo4j_session.run(
            "MATCH (c:AzureRedisCache{id: $id}) RETURN c.publicContext AS ctx", id=open_all['id'],
        ).single()['ctx'],
    )
    assert context['resource'] == open_all['id']
    assert context['resourceType'] == 'azure-database-redis-cluster'
    [detail] = context['context']
    assert detail['exposureTypes'] == ['unrestricted_firewall']
    assert detail['hostName'] == 'open-all.redis.cache.windows.net'
    assert detail['firewallRules'] == [
        {'firewallRuleId': f"{open_all['id']}/firewallRules/all", 'startIp': '0.0.0.0', 'endIp': '255.255.255.255'},
    ]
    assert neo4j_session.run(
        "MATCH (c:AzureRedisCache{id: $id}) RETURN c.publicContext AS ctx", id=stale['id'],
    ).single()['ctx'] is None
