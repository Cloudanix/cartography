"""
Azure Cache for Redis fetchers fed real SDK models (deserialized from ARM REST payloads):
the network fields the loader and exposure job read must arrive, and a failed firewall
read must be told apart from a cache that has no rules.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

from azure.core.exceptions import HttpResponseError
from azure.mgmt.redis import models

from cartography.intel.azure import redis

PARAMS = {'UPDATE_TAG': 1}
SUB = '00-00'
CACHE_ID = f'/subscriptions/{SUB}/resourceGroups/RG-Cache/providers/Microsoft.Cache/Redis/cache1'
SUBNET_ID = f'/subscriptions/{SUB}/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vn/subnets/redis'
CACHE = {'id': CACHE_ID, 'name': 'cache1', 'resource_group': 'rg-cache'}


def _cache(**properties):
    return models.RedisResource.deserialize({
        'id': CACHE_ID, 'name': 'cache1', 'type': 'Microsoft.Cache/Redis', 'location': 'eastus',
        'properties': {
            'sku': {'name': 'Premium', 'family': 'P', 'capacity': 1},
            'hostName': 'cache1.redis.cache.windows.net', 'port': 6379, 'sslPort': 6380,
            'redisVersion': '6.0', 'provisioningState': 'Succeeded',
            **properties,
        },
    })


def _rule(name, start, end):
    return models.RedisFirewallRule.deserialize({
        'id': f'{CACHE_ID}/firewallRules/{name}', 'name': f'cache1/{name}',
        'properties': {'startIP': start, 'endIP': end},
    })


def test_cache_network_fields_arrive():
    client = MagicMock()
    client.redis.list_by_subscription.return_value = [
        _cache(
            enableNonSslPort=True, minimumTlsVersion='1.0', publicNetworkAccess='Disabled',
            subnetId=SUBNET_ID, staticIP='10.0.0.4',
            privateEndpointConnections=[{'id': f'{CACHE_ID}/privateEndpointConnections/pe'}],
        ),
    ]

    [item] = redis.transform_caches(redis.get_caches(client), None, PARAMS)

    assert item['id'] == CACHE_ID
    assert item['resource_group'] == 'rg-cache'
    assert (item['sku_name'], item['sku_family'], item['sku_capacity']) == ('Premium', 'P', 1)
    assert item['enable_non_ssl_port'] is True
    assert item['minimum_tls_version'] == '1.0'
    assert item['public_network_access'] == 'Disabled'
    assert item['subnet_id'] == SUBNET_ID
    assert item['static_ip'] == '10.0.0.4'
    assert item['host_name'] == 'cache1.redis.cache.windows.net'
    assert (item['port'], item['ssl_port']) == (6379, 6380)
    assert item['redis_version'] == '6.0'
    assert item['private_endpoint_connection_count'] == 1


def test_cache_without_network_settings():
    client = MagicMock()
    client.redis.list_by_subscription.return_value = [_cache()]

    [item] = redis.transform_caches(redis.get_caches(client), None, PARAMS)

    assert item['public_network_access'] is None
    assert item['subnet_id'] is None
    assert item['private_endpoint_connection_count'] == 0


def test_region_filter():
    client = MagicMock()
    client.redis.list_by_subscription.return_value = [_cache()]

    assert redis.transform_caches(redis.get_caches(client), ['westus'], PARAMS) == []
    assert len(redis.transform_caches(redis.get_caches(client), ['eastus'], PARAMS)) == 1


def test_list_error_returns_empty():
    client = MagicMock()
    client.redis.list_by_subscription.side_effect = HttpResponseError('denied')

    assert redis.get_caches(client) == []


def test_firewall_rules_arrive_with_address_count():
    client = MagicMock()
    client.firewall_rules.list.return_value = [
        _rule('all', '0.0.0.0', '255.255.255.255'),
        _rule('office', '203.0.113.10', '203.0.113.10'),
        _rule('bad', 'not-an-ip', '1.1.1.1'),
    ]

    rules = redis.get_firewall_rules(client, CACHE)

    client.firewall_rules.list.assert_called_once_with('rg-cache', 'cache1')
    assert [(r['start_ip_address'], r['end_ip_address'], r['address_count']) for r in rules] == [
        ('0.0.0.0', '255.255.255.255', 4294967296),
        ('203.0.113.10', '203.0.113.10', 1),
        ('not-an-ip', '1.1.1.1', None),
    ]
    assert {r['cache_id'] for r in rules} == {CACHE_ID}


def test_firewall_error_is_not_an_empty_list():
    client = MagicMock()
    client.firewall_rules.list.side_effect = HttpResponseError('throttled')

    assert redis.get_firewall_rules(client, CACHE) is None


@patch.object(redis, 'cleanup')
@patch.object(redis, 'load_firewall_rules')
@patch.object(redis, 'load_caches')
@patch.object(redis, 'get_client')
def test_sync_marks_failed_firewall_read_on_the_cache(get_client, load_caches, load_firewall_rules, _cleanup):
    client = get_client.return_value
    client.redis.list_by_subscription.return_value = [_cache()]
    client.firewall_rules.list.side_effect = HttpResponseError('throttled')

    redis.sync(MagicMock(), MagicMock(), SUB, 1, PARAMS, None)

    [cache] = load_caches.call_args.args[2]
    assert cache['firewall_rules_fetched'] is False
    assert load_firewall_rules.call_args.args[1] == []
