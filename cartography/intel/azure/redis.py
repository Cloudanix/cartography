"""
Azure Cache for Redis (Microsoft.Cache/Redis). Redis Enterprise (Microsoft.Cache/redisEnterprise)
is a separate API and is not synced here.

API calls per subscription: 1 paged redis.list_by_subscription, plus 1 firewall_rules.list per cache
(N caches -> N + 1 calls, no sleeps). Both are granted by the Reader role
(Microsoft.Cache/redis/read, Microsoft.Cache/redis/firewallRules/read).
"""
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import neo4j
from azure.core.exceptions import HttpResponseError

from .sql import _firewall_rule_address_count
from .util.console_link import safe_console_link
from .util.credentials import Credentials
from .util.sdk_models import as_legacy_dict
from .util.timing import get_timing_policy
from cartography.client.core.tx import load_graph_data
from cartography.util import get_azure_resource_group_name
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


def get_client(credentials: Credentials, subscription_id: str) -> Any:
    # Imported here so a deploy that has not installed azure-mgmt-redis yet fails only this
    # service (isolated by the per-service try/except), not every Azure sync at import time.
    from azure.mgmt.redis import RedisManagementClient
    return RedisManagementClient(credentials, subscription_id, per_call_policies=[get_timing_policy()])


@timeit
def get_caches(client: Any) -> List[Dict]:
    try:
        return [as_legacy_dict(cache) for cache in client.redis.list_by_subscription()]
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving Azure Cache for Redis instances - {e}")
        return []


@timeit
def get_firewall_rules(client: Any, cache: Dict) -> Optional[List[Dict]]:
    """
    Firewall rules of one cache. None (not []) when the read fails, so the exposure job can
    tell "no rules" (open to every IP) from "rules unknown" (kept public, firewall_not_evaluated).
    """
    try:
        rules = [as_legacy_dict(rule) for rule in client.firewall_rules.list(cache['resource_group'], cache['name'])]
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving firewall rules for Redis cache {cache['id']} - {e}")
        return None
    for rule in rules:
        rule['cache_id'] = cache['id']
        rule['start_ip_address'] = rule.get('start_ip')
        rule['end_ip_address'] = rule.get('end_ip')
        rule['address_count'] = _firewall_rule_address_count(rule)
    return rules


@timeit
def transform_caches(caches: List[Dict], regions: Optional[List[str]], common_job_parameters: Dict) -> List[Dict]:
    result = []
    for cache in caches:
        if regions and cache.get('location') not in regions:
            continue
        sku = cache.get('sku') or {}
        result.append({
            'id': cache['id'],
            'name': cache.get('name'),
            'type': cache.get('type'),
            'location': cache.get('location'),
            'resource_group': get_azure_resource_group_name(cache['id']),
            'sku_name': sku.get('name'),
            'sku_family': sku.get('family'),
            'sku_capacity': sku.get('capacity'),
            'enable_non_ssl_port': cache.get('enable_non_ssl_port'),
            'minimum_tls_version': cache.get('minimum_tls_version'),
            'public_network_access': cache.get('public_network_access'),
            'redis_version': cache.get('redis_version'),
            'subnet_id': cache.get('subnet_id'),
            'static_ip': cache.get('static_ip'),
            'host_name': cache.get('host_name'),
            'port': cache.get('port'),
            'ssl_port': cache.get('ssl_port'),
            'provisioning_state': cache.get('provisioning_state'),
            'private_endpoint_connection_count': len(cache.get('private_endpoint_connections') or []),
            'consolelink': safe_console_link(cache['id'], common_job_parameters),
        })
    return result


def load_caches(neo4j_session: neo4j.Session, subscription_id: str, caches: List[Dict], update_tag: int) -> None:
    query = """
    UNWIND $DictList AS cache
    MERGE (c:AzureRedisCache{id: cache.id})
    ON CREATE SET c.firstseen = timestamp()
    SET c.name = cache.name,
    c.type = cache.type,
    c.location = cache.location,
    c.region = cache.location,
    c.resourcegroup = cache.resource_group,
    c.sku_name = cache.sku_name,
    c.sku_family = cache.sku_family,
    c.sku_capacity = cache.sku_capacity,
    c.enable_non_ssl_port = cache.enable_non_ssl_port,
    c.minimum_tls_version = cache.minimum_tls_version,
    c.public_network_access = cache.public_network_access,
    c.redis_version = cache.redis_version,
    c.subnet_id = cache.subnet_id,
    c.static_ip = cache.static_ip,
    c.host_name = cache.host_name,
    c.port = cache.port,
    c.ssl_port = cache.ssl_port,
    c.provisioning_state = cache.provisioning_state,
    c.private_endpoint_connection_count = cache.private_endpoint_connection_count,
    c.firewall_rules_fetched = cache.firewall_rules_fetched,
    c.consolelink = coalesce(cache.consolelink, c.consolelink),
    c.lastupdated = $update_tag
    WITH c, cache
    MATCH (sub:AzureSubscription{id: $subscription_id})
    MERGE (sub)-[r:RESOURCE]->(c)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH c, cache, sub
    OPTIONAL MATCH (sub)-[:RESOURCE]->(rg:AzureResourceGroup)
    WHERE toLower(rg.name) = cache.resource_group
    FOREACH (_ IN CASE WHEN rg IS NULL THEN [] ELSE [1] END |
        MERGE (c)-[g:RESOURCE_GROUP]->(rg)
        ON CREATE SET g.firstseen = timestamp()
        SET g.lastupdated = $update_tag
    )
    WITH c, cache
    OPTIONAL MATCH (s:AzureNetworkSubnet{id: cache.subnet_id})
    FOREACH (_ IN CASE WHEN s IS NULL THEN [] ELSE [1] END |
        MERGE (c)-[n:SUBNET]->(s)
        ON CREATE SET n.firstseen = timestamp()
        SET n.lastupdated = $update_tag
    )
    """
    load_graph_data(neo4j_session, query, caches, subscription_id=subscription_id, update_tag=update_tag)


def load_firewall_rules(neo4j_session: neo4j.Session, rules: List[Dict], update_tag: int) -> None:
    query = """
    UNWIND $DictList AS rule
    MATCH (c:AzureRedisCache{id: rule.cache_id})
    MERGE (fw:AzureRedisFirewallRule{id: rule.id})
    ON CREATE SET fw.firstseen = timestamp()
    SET fw.name = rule.name,
    fw.start_ip_address = rule.start_ip_address,
    fw.end_ip_address = rule.end_ip_address,
    fw.address_count = rule.address_count,
    fw.lastupdated = $update_tag
    MERGE (c)-[r:HAS]->(fw)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """
    load_graph_data(neo4j_session, query, rules, update_tag=update_tag)


def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_redis_cache_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, credentials: Credentials, subscription_id: str, update_tag: int,
    common_job_parameters: Dict, regions: Optional[List[str]] = None,
) -> None:
    logger.info("Syncing Azure Cache for Redis for subscription '%s'.", subscription_id)
    client = get_client(credentials, subscription_id)
    caches = transform_caches(get_caches(client), regions, common_job_parameters)

    rules: List[Dict] = []
    for cache in caches:
        cache_rules = get_firewall_rules(client, cache)
        cache['firewall_rules_fetched'] = cache_rules is not None
        rules.extend(cache_rules or [])

    load_caches(neo4j_session, subscription_id, caches, update_tag)
    load_firewall_rules(neo4j_session, rules, update_tag)
    cleanup(neo4j_session, common_job_parameters)
