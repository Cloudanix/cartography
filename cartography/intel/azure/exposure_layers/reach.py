"""
Azure L1 (public) + L2 (internet reachable) per resource type. Each reader returns
{node_id: Reach} for EVERY node of its label in the subscription, so a node that stopped
being reachable is rewritten with false.

    AzureNetworkInterface        own public IP, subnet NSG + NIC NSG
    AzureNetworkLoadBalancer     public frontend + rule, answers when a backend is open
    NIC / VMSS behind an LB      backend port of a public LB rule / NAT rule / NAT pool
    App Gateway / Azure Firewall listener / DNAT port; backends via gateways.py
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
from typing import Set
from typing import Tuple

import neo4j

from cartography.intel.azure.exposure_layers import gateways
from cartography.intel.azure.exposure_layers.network import add_gated_path
from cartography.intel.azure.exposure_layers.network import for_sku
from cartography.intel.azure.exposure_layers.network import Gate
from cartography.intel.azure.exposure_layers.network import gate
from cartography.intel.azure.exposure_layers.network import nsg_open
from cartography.intel.azure.exposure_layers.network import read_nsg_rules
from cartography.intel.azure.exposure_layers.network import read_subnets
from cartography.intel.azure.exposure_layers.network import Results
from cartography.intel.azure.exposure_layers.network import SubnetFacts
from cartography.intel.azure.exposure_layers.network import SUBSCRIPTION
from cartography.intel.azure.exposure_layers.network import Target
from cartography.intel.azure.exposure_layers.network import world_denies
from cartography.intel.exposure.layers import BLOCK_NO_LISTENER
from cartography.intel.exposure.layers import BLOCK_NOT_ALLOWED
from cartography.intel.exposure.layers import BLOCK_UNKNOWN_NEXT_HOP
from cartography.intel.exposure.layers import hop
from cartography.intel.exposure.layers import HOP_BACKEND
from cartography.intel.exposure.layers import HOP_LISTENER
from cartography.intel.exposure.layers import HOP_PUBLIC_IP
from cartography.intel.exposure.layers import HOP_SERVICE
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.exposure.rules import is_world

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
# exposure_paths[].entry types: where internet traffic first lands.
ENTRY_PUBLIC_IP = "public_ip"
ENTRY_INSTANCE_PUBLIC_IP = "public_ip_per_instance"
ENTRY_LOAD_BALANCER = "load_balancer"
ENTRY_ENDPOINT = "public_endpoint"
DETAIL_NO_RULE = "no_rule_on_public_frontend"
DETAIL_BACKENDS_CLOSED = "no_backend_admits_backend_port"
ANY_PORT = "*"


def _enabled(public_network_access: Optional[str]) -> bool:
    """None (unknown) is not Disabled, as in the existing exposure jobs."""
    return str(public_network_access or "").lower() != DISABLED


def _allows(default_action: Optional[str]) -> bool:
    return str(default_action or ALLOW).lower() == ALLOW


def merge(into: Reach, other: Reach) -> None:
    """
    ponytail: paths merge by via, so two NICs of a VM with their own public IPs share one
    direct_ipv4 path (first NIC's entry, both NICs' hops). Key paths by entry if that misleads.
    """
    into.public_reasons |= other.public_reasons
    into.ports = into.ports | other.ports
    into.via |= other.via
    for via, path in other.paths.items():
        into.add_path(path["ports"], via, path["hops"], path["entry"])
    into.blocked.extend(b for b in other.blocked if b not in into.blocked)


# ---------------------------------------------------------------- compute + load balancers


def direct_entry(row: Dict) -> Tuple[List[Dict], Dict]:
    """
    Hops and entry of a NIC / VMSS reached on its own public IP.
    ponytail: a NIC with several public IPs names the first as entry; per-instance VMSS IPs are
    not ingested, so the scale set itself is the entry.
    """
    pips = sorted(row["pips"], key=lambda p: p["id"])
    if not pips:
        return [], {"type": ENTRY_INSTANCE_PUBLIC_IP, "id": row["id"]}
    entry = {"type": ENTRY_PUBLIC_IP, "id": pips[0]["id"], "address": pips[0]["address"]}
    return [hop(HOP_PUBLIC_IP, p["id"]) for p in pips], entry


def attachments(
    rows: List[Dict], label: str, reason: str, subnets: Dict, nsgs: Dict, denies: Set[str],
) -> Tuple[Dict, Dict]:
    """NICs and VMSS: direct path through their own public IP. Returns (reaches, gates)."""
    reaches: Dict[str, Reach] = {}
    gates: Dict[Target, Gate] = {}
    for row in rows:
        through = gate(row["subnets"], row["nsgs"], subnets, nsgs, denies)
        reach = Reach()
        if row["public"]:
            reach.public_reasons.add(reason)
            hops, entry = direct_entry(row)
            add_gated_path(reach, PortSet.everything(), for_sku(through, row["skus"]), VIA_DIRECT, hops, entry)
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


def lb_rule_text(rule: Dict) -> str:
    """'tcp 443 -> 8080'; HA-ports rules (port 0) show '*'."""
    lo, hi = rule.get("frontend_port_start"), rule.get("frontend_port_end")
    front = f"{lo}-{hi}" if lo and hi and hi != lo else str(lo or ANY_PORT)
    return f"{str(rule.get('protocol') or ANY_PORT).lower()} {front} -> {rule.get('backend_port') or ANY_PORT}"


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
    pip = next(f["pip"] for f in lb_row["public_frontends"] if f["id"] == rule["frontend_ip_configuration_id"])
    hops = [hop(HOP_PUBLIC_IP, pip), hop(HOP_LISTENER, rule.get("id"), lb_rule_text(rule))]
    entry = {"type": ENTRY_LOAD_BALANCER, "id": lb_row["id"]}
    opened = [
        add_gated_path(results[label][tid], ports, for_sku(gates[(label, tid)], [lb_row["sku"]]), via, hops, entry)
        for label, tid in targets
    ]
    if not targets or any(opened):
        lb.add_path(frontend_ports(rule), VIA_FRONTEND, hops, entry)
        return
    blind = sorted({b for t in targets for b in gates[t].blind})
    lb.via.update(blind)
    reason = BLOCK_UNKNOWN_NEXT_HOP if blind else BLOCK_NOT_ALLOWED
    lb.block(HOP_BACKEND, rule.get("id"), reason, ports, DETAIL_BACKENDS_CLOSED)


def load_balancers(rows: List[Dict], index: BackendIndex, gates: Dict[Target, Gate], results: Results) -> Dict:
    """public_frontends: [{id: lowercased frontend id, pip: its public IP id}]."""
    out = {}
    for row in rows:
        reach = Reach()
        public = {f["id"] for f in row["public_frontends"]}
        routed = [r for r in row["rules"] if r.get("frontend_ip_configuration_id") in public]
        if public:
            reach.public_reasons.add(REASON_FRONTEND)
        if public and not routed:
            reach.block(HOP_LISTENER, row["id"], BLOCK_NO_LISTENER, detail=DETAIL_NO_RULE)
        for rule in routed:
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


def _endpoint(node_id: str, public: bool, opened: bool, ports: PortSet, reason: str = REASON_ENDPOINT) -> Reach:
    """The service's own firewall is the only hop; when it admits nobody that is the blocker."""
    reach = Reach()
    if not public:
        return reach
    reach.public_reasons.add(reason)
    if opened:
        reach.add_path(ports, VIA_ENDPOINT, [hop(HOP_SERVICE, node_id)], {"type": ENTRY_ENDPOINT, "id": node_id})
    else:
        reach.block(HOP_SERVICE, node_id, BLOCK_NOT_ALLOWED)
    return reach


def network_acl_endpoints(rows: List[Dict]) -> Dict[str, Reach]:
    """Storage, Key Vault, ACR: open when public access is on and the default action allows."""
    return {
        r["id"]: _endpoint(
            r["id"], _enabled(r["pna"]), _allows(r["default_action"]), HTTP_HTTPS if r["http"] else HTTPS,
        )
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
        out[r["id"]] = _endpoint(r["id"], _enabled(r["pna"]), opened, cosmos_ports(r))
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
        out[r["id"]] = _endpoint(r["id"], public, opened, PortSet.of(TCP, port, port) if port else PortSet.of(TCP))
    return out


def function_apps(rows: List[Dict]) -> Dict[str, Reach]:
    out = {}
    for r in rows:
        public = not r["host_names_disabled"] and _enabled(r["pna"])
        restricted = str(r["default_action"] or "").lower() == DENY and r["open_restriction"] is False
        out[r["id"]] = _endpoint(r["id"], public, not restricted, HTTP_HTTPS)
    return out


def aks_clusters(rows: List[Dict]) -> Dict[str, Reach]:
    return {
        r["id"]: _endpoint(
            r["id"], not r["private"], not r["ranges"] or any(is_world(c) for c in r["ranges"]), HTTPS,
            REASON_API_SERVER,
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
    collect(DISTINCT pip {{.id, address: pip.ipAddress}}) AS pips,
    collect(DISTINCT toLower(ipc.id)) AS ipconfigs, collect(DISTINCT ipc.private_ip_address) AS private_ips
"""

# ponytail: the per-instance public IP SKU of a scale set is not ingested, so it counts as Basic (open).
# LB and App Gateway pool ids never collide, so one pool index serves both front doors.
_VMSS_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(v:AzureVirtualMachineScaleSet)
RETURN v.id AS id, coalesce(v.public_ip_per_instance, false) AS public, [] AS skus, [] AS pips,
    coalesce(v.lb_backend_pool_ids, []) + coalesce(v.appgw_backend_pool_ids, []) AS pools,
    coalesce(v.lb_inbound_nat_lb_ids, []) AS nat_lbs,
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
    -[:MEMBER_PUBLIC_IP_ADDRESS]->(pip:AzurePublicIPAddress)
WITH lb, [f IN collect(DISTINCT {{id: toLower(fe.id), pip: pip.id}}) WHERE f.id IS NOT NULL] AS public_frontends
OPTIONAL MATCH (lb)-[:HAS]->(r:AzureLoadBalancerRule)
RETURN lb.id AS id, lb.sku AS sku, public_frontends, collect(r {{
    .id, .kind, .protocol, .frontend_port_start, .frontend_port_end, .backend_port,
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


def front_door_backends(
    nic_rows: List[Dict], vmss_rows: List[Dict], index: BackendIndex,
    subnets: Dict[str, SubnetFacts], nsg_rules: Dict[str, List[Dict]], nsgs: Dict[str, PortSet], results: Results,
) -> gateways.Backends:
    members = {(NIC, r["id"]): (r["subnets"], r["nsgs"]) for r in nic_rows}
    members.update({(VMSS, r["id"]): (r["subnets"], r["nsgs"]) for r in vmss_rows})
    return gateways.Backends(
        index.by_ipconfig, index.by_pool, gateways.nics_by_ip(nic_rows, NIC), members,
        subnets, nsg_rules, nsgs, results, world_denies(nsg_rules),
    )


def _compute_paths(q: Callable[[str], List[Dict]], subnets: Dict, nsg_rules: Dict[str, List[Dict]]) -> Results:
    nsgs = {nsg_id: nsg_open(rules) for nsg_id, rules in nsg_rules.items()}
    denies = world_denies(nsg_rules)
    nic_rows, vmss_rows = q(_NIC_QUERY), q(_VMSS_QUERY)
    nics, nic_gates = attachments(nic_rows, NIC, REASON_PUBLIC_IP, subnets, nsgs, denies)
    vmss, vmss_gates = attachments(vmss_rows, VMSS, REASON_PER_INSTANCE_IP, subnets, nsgs, denies)
    results: Results = {NIC: nics, VMSS: vmss}
    index = backend_index(nic_rows, vmss_rows, q(_POOL_QUERY))
    results[LB] = load_balancers(q(_LB_QUERY), index, {**nic_gates, **vmss_gates}, results)
    backends = front_door_backends(nic_rows, vmss_rows, index, subnets, nsg_rules, nsgs, results)
    results.update(gateways.compute(q, backends))
    results[VM] = union_of(q(_VM_QUERY), "nics", nics)
    return results


def compute(session: neo4j.Session, params: Dict) -> Results:
    """All Azure L1/L2 results for one subscription."""
    def q(query: str) -> List[Dict]:
        return [dict(r) for r in session.run(query, **params)]

    results = _compute_paths(q, read_subnets(session, params), read_nsg_rules(session, params))
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
