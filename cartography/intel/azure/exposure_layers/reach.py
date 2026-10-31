"""
Azure L1 (public) + L2 (internet reachable) per resource type. Each reader returns
{node_id: Reach} for EVERY node of its label in the subscription, so a node that stopped
being reachable is rewritten with false.

    AzureNetworkInterface        own public IP, subnet NSG + NIC NSG
    AzureNetworkLoadBalancer     public frontend + rule, answers when a backend is open
    NIC / VMSS behind an LB      backend port of a public LB rule / NAT rule / NAT pool
    AzureVirtualMachine          union of its NICs
    AzureVirtualMachineScaleSet  per-instance public IP or LB, NSGs from its NIC config
    PaaS                         public network access + firewall semantics of the
                                 existing azure_*_asset_exposure jobs, on the service port
"""
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.azure.exposure_layers.network import add_gated_path
from cartography.intel.azure.exposure_layers.network import for_sku
from cartography.intel.azure.exposure_layers.network import Gate
from cartography.intel.azure.exposure_layers.network import gate
from cartography.intel.azure.exposure_layers.network import read_nsgs
from cartography.intel.azure.exposure_layers.network import read_subnets
from cartography.intel.azure.exposure_layers.network import SUBSCRIPTION
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.exposure.rules import is_world

Results = Dict[str, Dict[str, Reach]]  # label -> node id -> Reach
Target = Tuple[str, str]  # (label, node id) an LB rule forwards to

NIC = "AzureNetworkInterface"
VM = "AzureVirtualMachine"
VMSS = "AzureVirtualMachineScaleSet"
LB = "AzureNetworkLoadBalancer"
STORAGE = "AzureStorageAccount"
BLOB_CONTAINER = "AzureStorageBlobContainer"
SQL_SERVER = "AzureSQLServer"
SQL_DATABASE = "AzureSQLDatabase"
COSMOS = "AzureCosmosDBAccount"
KEY_VAULT = "AzureKeyVault"
FUNCTION_APP = "AzureFunctionApp"
AKS = "AzureCluster"
ACR = "AzureContainerRegistry"

HTTPS = PortSet.of(TCP, 443, 443)
HTTP_HTTPS = PortSet.of(TCP, 80, 80) | HTTPS
COSMOS_MONGO = PortSet.of(TCP, 10255, 10255)
COSMOS_CASSANDRA = PortSet.of(TCP, 10350, 10350)
MONGO_KIND = "mongodb"
CASSANDRA_CAPABILITY = "EnableCassandra"
NAT_POOL = "inbound_nat_pool"
SQL_SERVER_ENGINE = "sqlserver"
# A SQL firewall rule wider than a /8 counts as the whole internet (azure_sql_asset_exposure).
SQL_WORLD_ADDRESS_COUNT = 16777216
DISABLED = "disabled"
ALLOW = "allow"
DENY = "deny"

VIA_DIRECT = "direct_ipv4"
VIA_LB = "lb:"
VIA_FRONTEND = "public_frontend"
VIA_ENDPOINT = "public_endpoint"
REASON_PUBLIC_IP = "public_ip"
REASON_PER_INSTANCE_IP = "public_ip_per_instance"
REASON_FRONTEND = "public_frontend"
REASON_ENDPOINT = "public_endpoint"
REASON_API_SERVER = "public_api_server"


def _enabled(public_network_access: Optional[str]) -> bool:
    """None (unknown) is not Disabled, as in the existing exposure jobs."""
    return str(public_network_access or "").lower() != DISABLED


def _allows(default_action: Optional[str]) -> bool:
    return str(default_action or ALLOW).lower() == ALLOW


def merge(into: Reach, other: Reach) -> None:
    into.public_reasons |= other.public_reasons
    into.ports = into.ports | other.ports
    into.via |= other.via


# ---------------------------------------------------------------- compute + load balancers


def attachments(rows: List[Dict], label: str, reason: str, subnets: Dict, nsgs: Dict) -> Tuple[Dict, Dict]:
    """NICs and VMSS: direct path through their own public IP. Returns (reaches, gates)."""
    reaches: Dict[str, Reach] = {}
    gates: Dict[Target, Gate] = {}
    for row in rows:
        through = gate(row["subnets"], row["nsgs"], subnets, nsgs)
        reach = Reach()
        if row["public"]:
            reach.public_reasons.add(reason)
            add_gated_path(reach, PortSet.everything(), for_sku(through, row["skus"]), VIA_DIRECT)
        reaches[row["id"]] = reach
        gates[(label, row["id"])] = through
    return reaches, gates


@dataclass
class BackendIndex:
    """Lowercased pool / ip configuration / LB ids -> the NICs and VMSS behind them."""
    by_pool: Dict[str, List[Target]]
    by_ipconfig: Dict[str, Target]
    by_nat_lb: Dict[str, List[Target]]

    def targets(self, lb_id: str, rule: Dict) -> List[Target]:
        found = [t for pool in rule.get("backend_pool_ids") or [] for t in self.by_pool.get(pool, [])]
        ipconfig = self.by_ipconfig.get(rule.get("backend_ip_configuration_id") or "")
        if ipconfig:
            found.append(ipconfig)
        if rule.get("kind") == NAT_POOL:
            found += self.by_nat_lb.get(lb_id.lower(), [])
        return sorted(set(found))


def backend_index(nic_rows: List[Dict], vmss_rows: List[Dict], pool_rows: List[Dict]) -> BackendIndex:
    by_pool: Dict[str, List[Target]] = defaultdict(list)
    by_nat_lb: Dict[str, List[Target]] = defaultdict(list)
    for row in pool_rows:
        by_pool[row["pool"]] += [(NIC, nic) for nic in row["nics"]]
    for row in vmss_rows:
        for pool in row["pools"]:
            by_pool[pool].append((VMSS, row["id"]))
        for lb_id in row["nat_lbs"]:
            by_nat_lb[lb_id].append((VMSS, row["id"]))
    by_ipconfig = {ipc: (NIC, row["id"]) for row in nic_rows for ipc in row["ipconfigs"]}
    return BackendIndex(by_pool, by_ipconfig, by_nat_lb)


def backend_ports(rule: Dict) -> PortSet:
    # HA-ports rules (protocol All, port 0) forward every port.
    port = rule.get("backend_port")
    return PortSet.of(rule.get("protocol"), port, port) if port else PortSet.of(rule.get("protocol"))


def frontend_ports(rule: Dict) -> PortSet:
    lo = rule.get("frontend_port_start")
    if not lo:
        return PortSet.of(rule.get("protocol"))
    return PortSet.of(rule.get("protocol"), lo, rule.get("frontend_port_end") or lo)


def _forward(
    lb_row: Dict, rule: Dict, index: BackendIndex, gates: Dict[Target, Gate], results: Results, lb: Reach,
) -> None:
    """
    One rule on a public frontend. Backends get the backend port through their NSGs; the LB
    answers on the frontend port when a backend is open, or when none is resolved (backends
    by IP address or in another subscription: upper bound).
    """
    targets = [t for t in index.targets(lb_row["id"], rule) if t in gates]
    via = f"{VIA_LB}{lb_row['id']}"
    ports = backend_ports(rule)
    opened = [
        add_gated_path(results[label][tid], ports, for_sku(gates[(label, tid)], [lb_row["sku"]]), via)
        for label, tid in targets
    ]
    if not targets or any(opened):
        lb.add_path(frontend_ports(rule), VIA_FRONTEND)
        return
    lb.via.update(b for t in targets for b in gates[t].blind)


def load_balancers(rows: List[Dict], index: BackendIndex, gates: Dict[Target, Gate], results: Results) -> Dict:
    out = {}
    for row in rows:
        reach = Reach()
        public = set(row["public_frontends"])
        if public:
            reach.public_reasons.add(REASON_FRONTEND)
        for rule in row["rules"]:
            if rule.get("frontend_ip_configuration_id") in public:
                _forward(row, rule, index, gates, results, reach)
        out[row["id"]] = reach
    return out


def union_of(rows: List[Dict], key: str, parts: Dict[str, Reach]) -> Dict[str, Reach]:
    """A node whose reach is the union of its parts (VM <- NICs)."""
    out = {}
    for row in rows:
        reach = Reach()
        for part_id in row[key]:
            if part_id in parts:
                merge(reach, parts[part_id])
        out[row["id"]] = reach
    return out


def copied(rows: List[Dict], parents: Dict[str, Reach]) -> Dict[str, Reach]:
    """Children answer on their parent's endpoint (SQL database, blob container)."""
    out = {}
    for row in rows:
        reach = Reach()
        if row["parent"] in parents:
            merge(reach, parents[row["parent"]])
        out[row["id"]] = reach
    return out


# ---------------------------------------------------------------- PaaS


def _endpoint(public: bool, opened: bool, ports: PortSet, reason: str = REASON_ENDPOINT) -> Reach:
    reach = Reach()
    if public:
        reach.public_reasons.add(reason)
        if opened:
            reach.add_path(ports, VIA_ENDPOINT)
    return reach


def network_acl_endpoints(rows: List[Dict]) -> Dict[str, Reach]:
    """Storage, Key Vault, ACR: open when public access is on and the default action allows."""
    return {
        r["id"]: _endpoint(_enabled(r["pna"]), _allows(r["default_action"]), HTTP_HTTPS if r["http"] else HTTPS)
        for r in rows
    }


def cosmos_ports(row: Dict) -> PortSet:
    ports = HTTPS
    if str(row.get("kind") or "").lower() == MONGO_KIND:
        ports = ports | COSMOS_MONGO
    if CASSANDRA_CAPABILITY in (row.get("capabilities") or []):
        ports = ports | COSMOS_CASSANDRA
    return ports


def cosmos_accounts(rows: List[Dict]) -> Dict[str, Reach]:
    """Open with no IP rule and no VNet filter, or with a world IP rule."""
    out = {}
    for r in rows:
        opened = not r["vnet_filter"] and (r["rule_count"] == 0 or any(is_world(ip) for ip in r["ipranges"]))
        out[r["id"]] = _endpoint(_enabled(r["pna"]), opened, cosmos_ports(r))
    return out


def sql_world_rule(rule: Dict) -> bool:
    count = rule.get("address_count")
    return count is None or count > SQL_WORLD_ADDRESS_COUNT


def sql_servers(rows: List[Dict]) -> Dict[str, Reach]:
    """Open with a world firewall rule, or when a non-SQL-Server firewall could not be read."""
    out = {}
    for r in rows:
        public = _enabled(r["pna"]) and not r["vnet"]
        unread = r["engine"] != SQL_SERVER_ENGINE and not r["fetched"]
        opened = unread or any(sql_world_rule(rule) for rule in r["rules"])
        port = r.get("port")
        out[r["id"]] = _endpoint(public, opened, PortSet.of(TCP, port, port) if port else PortSet.of(TCP))
    return out


def function_apps(rows: List[Dict]) -> Dict[str, Reach]:
    out = {}
    for r in rows:
        public = not r["host_names_disabled"] and _enabled(r["pna"])
        restricted = str(r["default_action"] or "").lower() == DENY and r["open_restriction"] is False
        out[r["id"]] = _endpoint(public, not restricted, HTTP_HTTPS)
    return out


def aks_clusters(rows: List[Dict]) -> Dict[str, Reach]:
    return {
        r["id"]: _endpoint(
            not r["private"], not r["ranges"] or any(is_world(c) for c in r["ranges"]), HTTPS, REASON_API_SERVER,
        )
        for r in rows
    }


# ---------------------------------------------------------------- graph reads

_NIC_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(nic:AzureNetworkInterface)
OPTIONAL MATCH (nic)-[:SUBNET]->(s:AzureNetworkSubnet)
OPTIONAL MATCH (nic)-[:MEMBER_NETWORK_SECURITY_GROUP]->(g:AzureNetworkSecurityGroup)
OPTIONAL MATCH (nic)-[:MEMBER_PUBLIC_IP_ADDRESS]->(pip:AzurePublicIPAddress)
OPTIONAL MATCH (nic)-[:CONTAINS]->(ipc:AzureNetworkInterfaceIPConfiguration)
RETURN nic.id AS id, collect(DISTINCT toLower(s.id)) AS subnets, collect(DISTINCT toLower(g.id)) AS nsgs,
    count(DISTINCT pip) > 0 AS public, collect(DISTINCT pip.sku) AS skus,
    collect(DISTINCT toLower(ipc.id)) AS ipconfigs
"""

# ponytail: the per-instance public IP SKU of a scale set is not ingested, so it counts as Basic (open).
_VMSS_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(v:AzureVirtualMachineScaleSet)
RETURN v.id AS id, coalesce(v.public_ip_per_instance, false) AS public, [] AS skus,
    coalesce(v.lb_backend_pool_ids, []) AS pools, coalesce(v.lb_inbound_nat_lb_ids, []) AS nat_lbs,
    coalesce(v.subnet_ids, []) AS subnets, coalesce(v.nsg_ids, []) AS nsgs
"""

_POOL_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(:AzureNetworkLoadBalancer)-[:HAS]->(p:AzureLoadBalancerBackendAddressPool)
    -[:HAS]->(:AzureNetworkInterfaceIPConfiguration)<-[:CONTAINS]-(nic:AzureNetworkInterface)
RETURN toLower(p.id) AS pool, collect(DISTINCT nic.id) AS nics
"""

_LB_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(lb:AzureNetworkLoadBalancer)
OPTIONAL MATCH (lb)-[:HAS]->(fe:AzureLoadBalancerFrontendIPConfiguration)
    -[:MEMBER_PUBLIC_IP_ADDRESS]->(:AzurePublicIPAddress)
WITH lb, collect(DISTINCT toLower(fe.id)) AS public_frontends
OPTIONAL MATCH (lb)-[:HAS]->(r:AzureLoadBalancerRule)
RETURN lb.id AS id, lb.sku AS sku, public_frontends, collect(r {{
    .kind, .protocol, .frontend_port_start, .frontend_port_end, .backend_port,
    .frontend_ip_configuration_id, .backend_pool_ids, .backend_ip_configuration_id
}}) AS rules
"""

_VM_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(vm:AzureVirtualMachine)
OPTIONAL MATCH (vm)-[:MEMBER_NETWORK_INTERFACE]->(nic:AzureNetworkInterface)
RETURN vm.id AS id, collect(DISTINCT nic.id) AS nics
"""

_STORAGE_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureStorageAccount)
RETURN n.id AS id, n.publicNetworkAccess AS pna, n.networkRuleDefaultAction AS default_action,
    coalesce(n.supportshttpstrafficonly, true) = false AS http
"""

_BLOB_CONTAINER_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(a:AzureStorageAccount)-[:USES]->(:AzureStorageBlobService)
    -[:CONTAINS]->(n:AzureStorageBlobContainer)
RETURN n.id AS id, a.id AS parent
"""

_KEY_VAULT_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureKeyVault)
RETURN n.id AS id, n.public_network_access AS pna, n.network_acl_default_action AS default_action, false AS http
"""

_ACR_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureContainerRegistry)
RETURN n.id AS id, n.public_network_access AS pna, n.network_rule_default_action AS default_action, false AS http
"""

_COSMOS_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureCosmosDBAccount)
RETURN n.id AS id, n.publicNetworkAccess AS pna, coalesce(n.virtualnetworkfilterenabled, false) AS vnet_filter,
    coalesce(n.iprulecount, size(coalesce(n.ipranges, []))) AS rule_count, coalesce(n.ipranges, []) AS ipranges,
    n.kind AS kind, coalesce(n.capabilities, []) AS capabilities
"""

_SQL_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureSQLServer)
OPTIONAL MATCH (n)-[:HAS]->(fw:AzureFirewallRule)
RETURN n.id AS id, n.publicNetworkAccess AS pna, coalesce(n.vnetIntegrated, false) AS vnet,
    coalesce(n.engine, 'sqlserver') AS engine, coalesce(n.firewall_rules_fetched, false) AS fetched, n.port AS port,
    collect(fw {{.start_ip_address, .end_ip_address, .address_count}}) AS rules
"""

_SQL_DATABASE_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(s:AzureSQLServer)-[:RESOURCE]->(n:AzureSQLDatabase)
RETURN n.id AS id, s.id AS parent
"""

_FUNCTION_APP_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureFunctionApp)
RETURN n.id AS id, coalesce(n.hostNamesDisabled, false) AS host_names_disabled, n.publicNetworkAccess AS pna,
    n.ipSecurityRestrictionsDefaultAction AS default_action, n.openAccessRestriction AS open_restriction
"""

_AKS_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureCluster)
RETURN n.id AS id, coalesce(n.enablePrivateCluster, false) AS private, coalesce(n.authorizedIPRanges, []) AS ranges
"""


def _compute_paths(q: Callable[[str], List[Dict]], subnets: Dict, nsgs: Dict) -> Results:
    nic_rows, vmss_rows = q(_NIC_QUERY), q(_VMSS_QUERY)
    nics, nic_gates = attachments(nic_rows, NIC, REASON_PUBLIC_IP, subnets, nsgs)
    vmss, vmss_gates = attachments(vmss_rows, VMSS, REASON_PER_INSTANCE_IP, subnets, nsgs)
    results: Results = {NIC: nics, VMSS: vmss}
    index = backend_index(nic_rows, vmss_rows, q(_POOL_QUERY))
    results[LB] = load_balancers(q(_LB_QUERY), index, {**nic_gates, **vmss_gates}, results)
    results[VM] = union_of(q(_VM_QUERY), "nics", nics)
    return results


def compute(session: neo4j.Session, params: Dict) -> Results:
    """All Azure L1/L2 results for one subscription."""
    def q(query: str) -> List[Dict]:
        return [dict(r) for r in session.run(query, **params)]

    results = _compute_paths(q, read_subnets(session, params), read_nsgs(session, params))
    storage = network_acl_endpoints(q(_STORAGE_QUERY))
    sql = sql_servers(q(_SQL_QUERY))
    results.update({
        STORAGE: storage,
        BLOB_CONTAINER: copied(q(_BLOB_CONTAINER_QUERY), storage),
        SQL_SERVER: sql,
        SQL_DATABASE: copied(q(_SQL_DATABASE_QUERY), sql),
        COSMOS: cosmos_accounts(q(_COSMOS_QUERY)),
        KEY_VAULT: network_acl_endpoints(q(_KEY_VAULT_QUERY)),
        ACR: network_acl_endpoints(q(_ACR_QUERY)),
        FUNCTION_APP: function_apps(q(_FUNCTION_APP_QUERY)),
        AKS: aks_clusters(q(_AKS_QUERY)),
    })
    return results
