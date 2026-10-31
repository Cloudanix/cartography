"""
Azure Cache for Redis loaders and cleanup, run for real on Neo4j.
"""
from cartography.intel.azure import redis

SUB = 'redis-sub'
OTHER_SUB = 'redis-other-sub'
TENANT = 'redis-tenant'
WORKSPACE = 'redis-ws'
PARAMS = {
    'UPDATE_TAG': 2, 'WORKSPACE_ID': WORKSPACE, 'AZURE_TENANT_ID': TENANT,
    'AZURE_SUBSCRIPTION_ID': SUB, 'LIMIT_SIZE': 1000,
}
PREFIX = f'/subscriptions/{SUB}/resourceGroups/RG-Cache/providers/Microsoft.Cache/Redis/'
SUBNET_ID = f'/subscriptions/{SUB}/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vn/subnets/redis'


def _cache(name, **kwargs):
    cache = {
        'id': f'{PREFIX}{name}', 'name': name, 'location': 'eastus', 'resource_group': 'rg-cache',
        'type': 'Microsoft.Cache/Redis', 'sku_name': 'Standard', 'sku_family': 'C', 'sku_capacity': 1,
        'enable_non_ssl_port': False, 'minimum_tls_version': '1.2', 'public_network_access': 'Enabled',
        'redis_version': '6.0', 'subnet_id': None, 'static_ip': None, 'host_name': f'{name}.redis.cache.windows.net',
        'port': 6379, 'ssl_port': 6380, 'provisioning_state': 'Succeeded', 'private_endpoint_connection_count': 0,
        'consolelink': None, 'firewall_rules_fetched': True,
    }
    cache.update(kwargs)
    return cache


def _rule(cache, name, start, end):
    rule = {
        'id': f"{cache['id']}/firewallRules/{name}", 'name': name, 'cache_id': cache['id'],
        'start_ip_address': start, 'end_ip_address': end,
    }
    rule['address_count'] = redis._firewall_rule_address_count(rule)
    return rule


def _seed(neo4j_session):
    neo4j_session.run(
        "MERGE (ws:CloudanixWorkspace{id: $ws})-[:OWNER]->(t:AzureTenant{id: $tenant})-[:RESOURCE]->"
        "(sub:AzureSubscription{id: $sub}) "
        "MERGE (t)-[:RESOURCE]->(other:AzureSubscription{id: $other}) "
        "MERGE (sub)-[:RESOURCE]->(:AzureResourceGroup{id: $rg_id, name: 'RG-Cache'}) "
        "MERGE (other)-[:RESOURCE]->(:AzureResourceGroup{id: $other_rg_id, name: 'RG-Cache'}) "
        "MERGE (:AzureNetworkSubnet{id: $subnet})",
        ws=WORKSPACE, tenant=TENANT, sub=SUB, other=OTHER_SUB,
        rg_id=f'/subscriptions/{SUB}/resourceGroups/RG-Cache', subnet=SUBNET_ID,
        other_rg_id=f'/subscriptions/{OTHER_SUB}/resourceGroups/RG-Cache',
    )


def test_load_caches_and_links(neo4j_session):
    _seed(neo4j_session)
    injected = _cache('injected', sku_name='Premium', subnet_id=SUBNET_ID, static_ip='10.0.0.4')
    public = _cache('public')
    redis.load_caches(neo4j_session, SUB, [injected, public], 2)
    redis.load_firewall_rules(neo4j_session, [_rule(public, 'office', '203.0.113.10', '203.0.113.10')], 2)

    rows = neo4j_session.run(
        "MATCH (:AzureSubscription{id: $sub})-[:RESOURCE]->(c:AzureRedisCache) "
        "OPTIONAL MATCH (c)-[:RESOURCE_GROUP]->(rg:AzureResourceGroup) "
        "OPTIONAL MATCH (c)-[:SUBNET]->(s:AzureNetworkSubnet) "
        "OPTIONAL MATCH (c)-[:HAS]->(fw:AzureRedisFirewallRule) "
        "RETURN c.name AS name, c.region AS region, c.sku_name AS sku, c.subnet_id AS subnet_id, "
        "collect(DISTINCT rg.id) AS rgs, collect(DISTINCT s.id) AS subnets, "
        "collect(DISTINCT [fw.start_ip_address, fw.end_ip_address, fw.address_count]) AS rules",
        sub=SUB,
    )
    actual = {r['name']: (r['region'], r['sku'], r['rgs'], r['subnets'], r['rules']) for r in rows}
    rg_id = f'/subscriptions/{SUB}/resourceGroups/RG-Cache'
    assert actual == {
        # Resource group links are scoped to the cache's own subscription (case-insensitive name).
        'injected': ('eastus', 'Premium', [rg_id], [SUBNET_ID], [[None, None, None]]),
        'public': ('eastus', 'Standard', [rg_id], [], [['203.0.113.10', '203.0.113.10', 1]]),
    }


def test_cleanup_removes_stale_caches_and_rules(neo4j_session):
    _seed(neo4j_session)
    gone = _cache('gone')
    kept = _cache('kept')
    redis.load_caches(neo4j_session, SUB, [gone, kept], 1)
    redis.load_firewall_rules(
        neo4j_session, [_rule(gone, 'a', '1.1.1.1', '1.1.1.1'), _rule(kept, 'old', '2.2.2.2', '2.2.2.2')], 1,
    )
    redis.load_caches(neo4j_session, SUB, [kept], 2)
    redis.load_firewall_rules(neo4j_session, [_rule(kept, 'new', '3.3.3.3', '3.3.3.3')], 2)

    redis.cleanup(neo4j_session, PARAMS)

    caches = {
        r['name'] for r in neo4j_session.run(
            "MATCH (c:AzureRedisCache) WHERE c.id STARTS WITH $p RETURN c.name AS name", p=PREFIX,
        )
    }
    rules = {
        r['name'] for r in neo4j_session.run(
            "MATCH (fw:AzureRedisFirewallRule) WHERE fw.id STARTS WITH $gone OR fw.id STARTS WITH $kept "
            "RETURN fw.name AS name",
            gone=gone['id'], kept=kept['id'],
        )
    }
    assert 'gone' not in caches and 'kept' in caches
    assert rules == {'new'}
