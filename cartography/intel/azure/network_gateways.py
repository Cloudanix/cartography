"""
Application Gateways and Azure Firewalls: the front doors that forward internet traffic to
private backends (docs/exposure-layers/plan.md, section 4). Read-only calls, all covered by
the Reader role (*/read):

    application_gateways.list_all()                     Microsoft.Network/applicationGateways/read
    azure_firewalls.list_all()                          Microsoft.Network/azureFirewalls/read
    firewall_policy_rule_collection_groups.list(rg, p)  Microsoft.Network/firewallPolicies/ruleCollectionGroups/read
                                                        (one call per firewall policy in use)

Graph:
    (:AzureSubscription)-[:RESOURCE]->(:AzureApplicationGateway)-[:HAS]->(:AzureApplicationGatewayRule)
    (:AzureApplicationGateway)-[:SUBNET]->(:AzureNetworkSubnet), -[:MEMBER_PUBLIC_IP_ADDRESS]->(:AzurePublicIPAddress)
    (:AzureNetworkInterface)-[:CONNECTED_TO]->(:AzureApplicationGateway)       backend NICs, as for load balancers
    (:AzureSubscription)-[:RESOURCE]->(:AzureFirewall)-[:HAS]->(:AzureFirewallNatRule)   DNAT rules only
    (:AzureFirewall)-[:SUBNET]->(:AzureNetworkSubnet), -[:MEMBER_PUBLIC_IP_ADDRESS]->(:AzurePublicIPAddress)
"""
import logging
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j
from azure.core.exceptions import HttpResponseError
from azure.mgmt.network import NetworkManagementClient

from .util.console_link import safe_console_link
from .util.sdk_models import as_legacy_dict
from cartography.util import get_azure_resource_group_name
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

APP_GATEWAY = "AzureApplicationGateway"
APP_GATEWAY_RULE = "AzureApplicationGatewayRule"
FIREWALL = "AzureFirewall"
FIREWALL_NAT_RULE = "AzureFirewallNatRule"
GLOBAL_LOCATION = "global"
DNAT = "dnat"
NAT_RULE_COLLECTION = "FirewallPolicyNatRuleCollection"
# /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Network/firewallPolicies/{name}
POLICY_ID_PARTS = 9
# Application Gateway sub-resource lists that routing rules reference by id.
_GATEWAY_COLLECTIONS = (
    "http_listeners", "frontend_ip_configurations", "frontend_ports", "backend_address_pools",
    "backend_http_settings_collection", "url_path_maps",
)


def _ref(item: Optional[Dict], key: str) -> str:
    """Lowercased id of a sub-resource reference; resources reference each other in mixed case."""
    ref = (item or {}).get(key) or {}
    return ref["id"].lower() if ref.get("id") else ""


def _raw_ids(items: Optional[List[Dict]], key: str) -> List[str]:
    """Ids as ARM spells them, to MATCH nodes the other loaders created with that spelling."""
    ids = {((i or {}).get(key) or {}).get("id") for i in items or []}
    return sorted(i for i in ids if i)


def _lower_ids(refs: Optional[List[Dict]]) -> List[str]:
    return sorted({r["id"].lower() for r in refs or [] if r.get("id")})


def _by_id(items: Optional[List[Dict]]) -> Dict[str, Dict]:
    return {i["id"].lower(): i for i in items or [] if i.get("id")}


def _in_regions(resource: Dict, regions: Optional[list]) -> bool:
    return regions is None or resource.get("location") in regions or resource.get("location") == GLOBAL_LOCATION


def _base(resource: Dict, common_job_parameters: Dict) -> Dict:
    sku = resource.get("sku") or {}
    return {
        "id": resource["id"],
        "name": resource.get("name"),
        "location": resource.get("location"),
        "resource_group": get_azure_resource_group_name(resource["id"]),
        "consolelink": safe_console_link(resource["id"], common_job_parameters),
        "sku_name": sku.get("name"),
        "sku_tier": sku.get("tier"),
    }


# ---------------------------------------------------------------- Application Gateway


def _route_targets(rule: Dict, path_maps: Dict[str, Dict]) -> List[Tuple[str, str, str]]:
    """(node id, pool id, settings id) for each backend a routing rule can send to."""
    path_map = path_maps.get(_ref(rule, "url_path_map"))
    if not path_map:
        return [(rule["id"], _ref(rule, "backend_address_pool"), _ref(rule, "backend_http_settings"))]
    default = (_ref(path_map, "default_backend_address_pool"), _ref(path_map, "default_backend_http_settings"))
    targets = [(rule["id"], *default)]
    for path_rule in path_map.get("path_rules") or []:
        if path_rule.get("id"):
            node_id = f"{rule['id']}/pathRules/{path_rule['id'].rsplit('/', 1)[-1]}"
            targets.append((node_id, _ref(path_rule, "backend_address_pool"), _ref(path_rule, "backend_http_settings")))
    return targets


def _flatten_route(node_id: str, rule: Dict, pool: Dict, settings: Dict, idx: Dict[str, Dict[str, Dict]]) -> Dict:
    listener = idx["http_listeners"].get(_ref(rule, "http_listener")) or {}
    frontend = idx["frontend_ip_configurations"].get(_ref(listener, "frontend_ip_configuration")) or {}
    port = idx["frontend_ports"].get(_ref(listener, "frontend_port")) or {}
    addresses = pool.get("backend_addresses") or []
    return {
        "id": node_id,
        "name": rule.get("name"),
        "frontend_public": bool(_ref(frontend, "public_ip_address")),
        "listener_protocol": listener.get("protocol"),
        "listener_port": port.get("port"),
        "backend_protocol": settings.get("protocol"),
        "backend_port": settings.get("port"),
        "backend_pool_id": pool["id"].lower(),
        "backend_ip_configuration_ids": _lower_ids(pool.get("backend_ip_configurations")),
        "backend_ip_addresses": sorted({a["ip_address"] for a in addresses if a.get("ip_address")}),
        "backend_fqdns": sorted({a["fqdn"] for a in addresses if a.get("fqdn")}),
    }


def gateway_rules(gateway: Dict) -> List[Dict]:
    """
    One AzureApplicationGatewayRule per routing target: a basic rule has one, a path-based rule
    its default plus one per path rule. Redirect-only rules have no backend and are skipped.
    """
    idx = {key: _by_id(gateway.get(key)) for key in _GATEWAY_COLLECTIONS}
    pools, settings = idx["backend_address_pools"], idx["backend_http_settings_collection"]
    routes = []
    for rule in gateway.get("request_routing_rules") or []:
        if not rule.get("id"):
            continue
        for node_id, pool_id, settings_id in _route_targets(rule, idx["url_path_maps"]):
            if pool_id in pools and settings_id in settings:
                routes.append(_flatten_route(node_id, rule, pools[pool_id], settings[settings_id], idx))
    return routes


def transform_application_gateway(gateway: Dict, common_job_parameters: Dict) -> Dict:
    """
    ponytail: WAF mode is read from the classic web_application_firewall_configuration only; with a
    WAF policy attached (waf_policy_id) the mode needs web_application_firewall_policies.list_all.
    """
    waf = gateway.get("web_application_firewall_configuration") or {}
    pools = gateway.get("backend_address_pools") or []
    return {
        **_base(gateway, common_job_parameters),
        "waf_enabled": waf.get("enabled"),
        "waf_mode": waf.get("firewall_mode"),
        "waf_policy_id": (gateway.get("firewall_policy") or {}).get("id"),
        "subnet_ids": _raw_ids(gateway.get("gateway_ip_configurations"), "subnet"),
        "public_ip_ids": _raw_ids(gateway.get("frontend_ip_configurations"), "public_ip_address"),
        "backend_ip_configuration_ids": sorted({
            c["id"] for pool in pools for c in pool.get("backend_ip_configurations") or [] if c.get("id")
        }),
        "rules": gateway_rules(gateway),
    }


@timeit
def get_application_gateways(
    client: NetworkManagementClient, regions: Optional[list], common_job_parameters: Dict,
) -> List[Dict]:
    try:
        gateways = [as_legacy_dict(g) for g in client.application_gateways.list_all()]
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving application gateways - {e}")
        return []
    return [transform_application_gateway(g, common_job_parameters) for g in gateways if _in_regions(g, regions)]


# ---------------------------------------------------------------- Azure Firewall


def _flatten_nat_rule(rule_id: str, rule: Dict, protocols: Optional[List[str]]) -> Dict:
    return {
        "id": rule_id,
        "name": rule.get("name"),
        "protocols": protocols or [],
        "source_addresses": rule.get("source_addresses") or [],
        "source_ip_groups": rule.get("source_ip_groups") or [],
        "destination_addresses": rule.get("destination_addresses") or [],
        "destination_ports": rule.get("destination_ports") or [],
        "translated_address": rule.get("translated_address"),
        "translated_fqdn": rule.get("translated_fqdn"),
        "translated_port": rule.get("translated_port"),
    }


def classic_dnat_rules(firewall: Dict) -> List[Dict]:
    """DNAT rules of classic nat_rule_collections (rules have no id of their own)."""
    return [
        _flatten_nat_rule(f"{collection['id']}/rules/{rule.get('name')}", rule, rule.get("protocols"))
        for collection in firewall.get("nat_rule_collections") or []
        if collection.get("id") and str((collection.get("action") or {}).get("type") or "").lower() == DNAT
        for rule in collection.get("rules") or []
    ]


def policy_dnat_rules(groups: List[Dict]) -> List[Dict]:
    """DNAT rules of a firewall policy's NAT rule collections (always action DNAT)."""
    rules = []
    for group in groups:
        for collection in group.get("rule_collections") or []:
            if collection.get("rule_collection_type") != NAT_RULE_COLLECTION:
                continue
            prefix = f"{group['id']}/ruleCollections/{collection.get('name')}/rules/"
            for rule in collection.get("rules") or []:
                rules.append(_flatten_nat_rule(prefix + str(rule.get("name")), rule, rule.get("ip_protocols")))
    return rules


def transform_firewall(firewall: Dict, common_job_parameters: Dict) -> Dict:
    """
    ponytail: Virtual WAN hub firewalls (hub_ip_addresses) carry no ip_configurations, so they get
    no public IP or subnet here; read hub_ip_addresses.public_i_ps if secured hubs matter.
    """
    ip_configurations = firewall.get("ip_configurations") or []
    private_ips = {c["private_ip_address"] for c in ip_configurations if c.get("private_ip_address")}
    return {
        **_base(firewall, common_job_parameters),
        "threat_intel_mode": firewall.get("threat_intel_mode"),
        "firewall_policy_id": (firewall.get("firewall_policy") or {}).get("id"),
        "private_ip_addresses": sorted(private_ips),
        "subnet_ids": _raw_ids(ip_configurations, "subnet"),
        "public_ip_ids": _raw_ids(ip_configurations, "public_ip_address"),
        "rules": classic_dnat_rules(firewall),
    }


def get_policy_dnat_rules(client: NetworkManagementClient, policy_id: str, subscription_id: str) -> List[Dict]:
    """
    ponytail: a policy in another subscription (client is per subscription) and rules inherited
    from a parent policy (base_policy) are not read; both need a client / call per policy owner.
    """
    parts = policy_id.split("/")
    if len(parts) != POLICY_ID_PARTS or parts[2].lower() != subscription_id.lower():
        logger.info(f"Skipping firewall policy outside subscription {subscription_id}: {policy_id}")
        return []
    try:
        groups = [as_legacy_dict(g) for g in client.firewall_policy_rule_collection_groups.list(parts[4], parts[8])]
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving rule collection groups of {policy_id} - {e}")
        return []
    return policy_dnat_rules(groups)


@timeit
def get_firewalls(
    client: NetworkManagementClient, subscription_id: str, regions: Optional[list], common_job_parameters: Dict,
) -> List[Dict]:
    try:
        raw = [as_legacy_dict(f) for f in client.azure_firewalls.list_all()]
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving azure firewalls - {e}")
        return []
    firewalls = [transform_firewall(f, common_job_parameters) for f in raw if _in_regions(f, regions)]
    policy_ids = {f["firewall_policy_id"] for f in firewalls if f["firewall_policy_id"]}
    policy_rules = {p: get_policy_dnat_rules(client, p, subscription_id) for p in policy_ids}
    for firewall in firewalls:
        firewall["rules"] += policy_rules.get(firewall["firewall_policy_id"], [])
    return firewalls


# ---------------------------------------------------------------- load


_NODE_QUERY = """
UNWIND $rows AS row
MERGE (n:{label}{{id: row.id}})
ON CREATE SET n.firstseen = timestamp()
SET n += row.props, n.region = row.props.location, n.lastupdated = $update_tag
WITH n
MATCH (owner:AzureSubscription{{id: $subscription_id}})
MERGE (owner)-[r:RESOURCE]->(n)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $update_tag
"""

_RULES_QUERY = """
UNWIND $rows AS row
MATCH (n:{label}{{id: row.id}})
UNWIND row.rules AS rule
MERGE (r:{rule_label}{{id: rule.id}})
ON CREATE SET r.firstseen = timestamp()
SET r += rule, r.lastupdated = $update_tag
MERGE (n)-[rel:HAS]->(r)
ON CREATE SET rel.firstseen = timestamp()
SET rel.lastupdated = $update_tag
"""

_LINK_QUERY = """
UNWIND $rows AS row
MATCH (n:{label}{{id: row.id}})
UNWIND row.{key} AS target_id
MATCH (t:{target}{{id: target_id}})
MERGE (n)-[r:{rel}]->(t)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $update_tag
"""

_BACKEND_NIC_QUERY = f"""
UNWIND $rows AS row
MATCH (n:{APP_GATEWAY}{{id: row.id}})
UNWIND row.backend_ip_configuration_ids AS ipc_id
MATCH (:AzureNetworkInterfaceIPConfiguration{{id: ipc_id}})<-[:CONTAINS]-(nic:AzureNetworkInterface)
MERGE (nic)-[r:CONNECTED_TO]->(n)
ON CREATE SET r.firstseen = timestamp()
SET r.lastupdated = $update_tag
"""

# Transform keys that become relationships, not node properties.
_LINK_KEYS = ("rules", "subnet_ids", "public_ip_ids", "backend_ip_configuration_ids")
# (transform key, relationship, target label) shared by gateways and firewalls.
_LINKS = (
    ("subnet_ids", "SUBNET", "AzureNetworkSubnet"),
    ("public_ip_ids", "MEMBER_PUBLIC_IP_ADDRESS", "AzurePublicIPAddress"),
)


def _load_tx(
    tx: neo4j.Transaction, label: str, rule_label: str, rows: List[Dict], subscription_id: str, update_tag: int,
) -> None:
    """Labels are module constants, never input, so formatting them into Cypher is safe."""
    node_rows = [{"id": r["id"], "props": {k: v for k, v in r.items() if k not in _LINK_KEYS}} for r in rows]
    tx.run(_NODE_QUERY.format(label=label), rows=node_rows, subscription_id=subscription_id, update_tag=update_tag)
    tx.run(_RULES_QUERY.format(label=label, rule_label=rule_label), rows=rows, update_tag=update_tag)
    for key, rel, target in _LINKS:
        tx.run(_LINK_QUERY.format(label=label, key=key, rel=rel, target=target), rows=rows, update_tag=update_tag)


def load_application_gateways(session: neo4j.Session, subscription_id: str, rows: List[Dict], update_tag: int) -> None:
    session.execute_write(_load_tx, APP_GATEWAY, APP_GATEWAY_RULE, rows, subscription_id, update_tag)
    session.run(_BACKEND_NIC_QUERY, rows=rows, update_tag=update_tag).consume()


def load_firewalls(session: neo4j.Session, subscription_id: str, rows: List[Dict], update_tag: int) -> None:
    session.execute_write(_load_tx, FIREWALL, FIREWALL_NAT_RULE, rows, subscription_id, update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session, client: NetworkManagementClient, subscription_id: str, update_tag: int,
    common_job_parameters: Dict, regions: Optional[list],
) -> None:
    gateways = get_application_gateways(client, regions, common_job_parameters)
    load_application_gateways(neo4j_session, subscription_id, gateways, update_tag)
    run_cleanup_job("azure_import_application_gateways_cleanup.json", neo4j_session, common_job_parameters)
    firewalls = get_firewalls(client, subscription_id, regions, common_job_parameters)
    load_firewalls(neo4j_session, subscription_id, firewalls, update_tag)
    run_cleanup_job("azure_import_azure_firewalls_cleanup.json", neo4j_session, common_job_parameters)
