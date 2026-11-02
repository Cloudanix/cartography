"""
Azure L5 (network half): which data stores a VM can open a connection to.

    (:AzureVirtualMachine)-[:CAN_NETWORK_REACH {ports, via}]->(:AzureSQLServer|AzureCosmosDBAccount)

Azure data stores are PaaS endpoints gated by their own firewall, not by the VM's NSG, so
a VM reaches a store that (in order of precedence, first match wins):
    firewall_ip_rule     admits one of the VM's public IPs
    azure_services_rule  admits all of Azure ("Allow Azure services", 0.0.0.0)
    public_endpoint      is internet reachable (L2)
The identity half (managed identity -> role assignments) already exists in the graph.

ponytail: VMs without a public IP egress through SNAT / NAT gateway addresses, which are
not resolved; private endpoints and VNet service endpoints are not walked; outbound NSG
rules are ignored. Resolve NAT gateway IPs and private endpoint subnets to tighten this.
"""
import ipaddress
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.azure.exposure_layers.network import Results
from cartography.intel.azure.exposure_layers.network import SUBSCRIPTION
from cartography.intel.azure.exposure_layers.reach import COSMOS
from cartography.intel.azure.exposure_layers.reach import cosmos_ports
from cartography.intel.azure.exposure_layers.reach import SQL_SERVER
from cartography.intel.azure.exposure_layers.reach import VM
from cartography.intel.exposure.layers import CAN_NETWORK_REACH
from cartography.intel.exposure.layers import merge_reach_edges
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.layers import reach_summaries
from cartography.intel.exposure.layers import set_node_properties
from cartography.intel.exposure.layers import write_reach_counts
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP

VIA_IP_RULE = "firewall_ip_rule"
VIA_AZURE_SERVICES = "azure_services_rule"
VIA_PUBLIC = "public_endpoint"
AZURE_SERVICES_IP = "0.0.0.0"
DISABLED = "disabled"

_VM_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(vm:AzureVirtualMachine)
OPTIONAL MATCH (vm)-[:MEMBER_NETWORK_INTERFACE]->(:AzureNetworkInterface)
    -[:MEMBER_PUBLIC_IP_ADDRESS]->(pip:AzurePublicIPAddress)
RETURN vm.id AS id, [ip IN collect(DISTINCT pip.ipAddress) WHERE ip IS NOT NULL] AS ips
"""

_SQL_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureSQLServer)
WHERE toLower(coalesce(n.publicNetworkAccess, '')) <> '{DISABLED}' AND NOT coalesce(n.vnetIntegrated, false)
OPTIONAL MATCH (n)-[:HAS]->(fw:AzureFirewallRule)
RETURN n.id AS id, n.port AS port,
    collect(CASE WHEN fw IS NULL THEN null ELSE [fw.start_ip_address, fw.end_ip_address, coalesce(fw.name, fw.id)] END)
        AS ranges
"""

_COSMOS_QUERY = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(n:AzureCosmosDBAccount)
WHERE toLower(coalesce(n.publicNetworkAccess, '')) <> '{DISABLED}'
RETURN n.id AS id, coalesce(n.allowAzureDatacenters, false) AS azure_services, coalesce(n.ipranges, []) AS cidrs,
    n.kind AS kind, coalesce(n.capabilities, []) AS capabilities
"""

_CLEANUP = f"""
MATCH {SUBSCRIPTION}-[:RESOURCE]->(:AzureVirtualMachine)-[r:{CAN_NETWORK_REACH}]->()
WHERE r.lastupdated <> $UPDATE_TAG
DELETE r
"""


def _in_range(ip: str, start: Optional[str], end: Optional[str]) -> bool:
    try:
        # SQL server firewall rules are IPv4 only.
        return ipaddress.IPv4Address(start) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(end)
    except (ValueError, TypeError):
        return False


def _in_cidr(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False


Admission = Tuple[str, Optional[str]]  # (via, admitted_by: the rule that let the VM in, when known)


def sql_via(vm_ips: Iterable[str], store: Dict, public: bool) -> Optional[Admission]:
    """How a VM gets through a SQL server firewall, or None. ranges: [[start, end, rule name], ...]."""
    ips = list(vm_ips)
    azure_services = [AZURE_SERVICES_IP, AZURE_SERVICES_IP]
    ranges = [r for r in store["ranges"] if list(r[:2]) != azure_services]
    for lo, hi, name in ranges:
        if any(_in_range(ip, lo, hi) for ip in ips):
            return VIA_IP_RULE, name
    if len(ranges) < len(store["ranges"]):
        return VIA_AZURE_SERVICES, VIA_AZURE_SERVICES
    return (VIA_PUBLIC, None) if public else None


def cosmos_via(vm_ips: Iterable[str], store: Dict, public: bool) -> Optional[Admission]:
    """How a VM gets through a Cosmos DB IP filter, or None. IP rules have no name: the CIDR is the rule."""
    ips = list(vm_ips)
    for cidr in store["cidrs"]:
        if any(_in_cidr(ip, cidr) for ip in ips):
            return VIA_IP_RULE, cidr
    if store["azure_services"]:
        return VIA_AZURE_SERVICES, VIA_AZURE_SERVICES
    return (VIA_PUBLIC, None) if public else None


ViaFn = Callable[[Iterable[str], Dict, bool], Optional[Admission]]


def reach_rows(
    vms: List[Dict], stores: List[Dict], via_fn: ViaFn, reach: Dict[str, Reach], ports_fn: Callable[[Dict], PortSet],
    label: str,
) -> List[Dict]:
    """Edge rows {src, dst, dst_type, ports, via, admitted_by} for every VM a store's firewall admits."""
    rows = []
    for store in stores:
        public = store["id"] in reach and not reach[store["id"]].ports.is_empty()
        ports = ports_fn(store).to_strings()
        for vm in vms:
            admitted = via_fn(vm["ips"], store, public)
            if admitted:
                row = {"src": vm["id"], "dst": store["id"], "dst_type": label, "ports": ports}
                rows.append({**row, "via": admitted[0], "admitted_by": admitted[1]})
    return rows


def _sql_ports(store: Dict) -> PortSet:
    port = store.get("port")
    return PortSet.of(TCP, port, port) if port else PortSet.of(TCP)


# (data store label, its firewall query, how a VM gets through, its service ports)
_STORES = (
    (SQL_SERVER, _SQL_QUERY, sql_via, _sql_ports),
    (COSMOS, _COSMOS_QUERY, cosmos_via, cosmos_ports),
)


def sync(session: neo4j.Session, params: Dict, reach: Results) -> None:
    """
    Write VM -> data store edges for one subscription, drop edges not seen this run, then the
    summaries: reachable stores on every VM, reverse counts on every store. Run after L2 is
    written (the counts read internet_reachable on the VMs).
    """
    def q(query: str) -> List[Dict]:
        return [dict(r) for r in session.run(query, **params)]

    tag = params["UPDATE_TAG"]
    vms = q(_VM_QUERY)
    edges: List[Dict] = []
    for label, query, via_fn, ports_fn in _STORES:
        rows = reach_rows(vms, q(query), via_fn, reach.get(label, {}), ports_fn, label)
        merge_reach_edges(session, VM, label, rows, tag)
        edges += rows
    session.run(_CLEANUP, **params).consume()
    set_node_properties(session, VM, reach_summaries([vm["id"] for vm in vms], edges), evaluated_at=tag)
    for label, *_ in _STORES:
        write_reach_counts(session, label, sorted(reach.get(label, {})), tag)
