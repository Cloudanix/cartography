"""
GCP L1 (public) + L2 (internet reachable) per resource type. Every reader returns
{node_id: Reach} for EVERY node of its label in the project, so a node that stopped being
reachable is rewritten with false.

    GCPInstance          external IP (route + firewall), or backend of an external forwarding rule
    GCPForwardingRule    EXTERNAL / EXTERNAL_MANAGED scheme, on its front-end ports
    GCPBackendService    reached by an external forwarding rule (directly or through its URL map)
    GKECluster           public endpoint with master authorized networks off or holding 0.0.0.0/0
    GCPSQLInstance       public IPv4 with an authorized network of 0.0.0.0/0, on the engine port
    GCPFunction          HTTP function with ingress ALLOW_ALL, or behind an external LB's serverless NEG
                         (ingress ALLOW_ALL / ALLOW_INTERNAL_AND_GCLB)
    GCPCloudRunService   ingress "all", or behind an external LB's serverless NEG (ingress "all" /
                         "internal-and-cloud-load-balancing")
    GCPBucket / GCPBigqueryDataset   Google API endpoint, always on 443; L3 decides who gets in
"""
from dataclasses import dataclass
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import neo4j

from cartography.intel.exposure.layers import ACCESS_AUTH
from cartography.intel.exposure.layers import AUTH_NONE
from cartography.intel.exposure.layers import BLOCK_NOT_ALLOWED
from cartography.intel.exposure.layers import hop
from cartography.intel.exposure.layers import HOP_BACKEND
from cartography.intel.exposure.layers import HOP_LISTENER
from cartography.intel.exposure.layers import HOP_SERVICE
from cartography.intel.exposure.layers import HOP_TARGET_GROUP
from cartography.intel.exposure.layers import Reach
from cartography.intel.exposure.ports import PortSet
from cartography.intel.exposure.ports import TCP
from cartography.intel.exposure.rules import is_world
from cartography.intel.gcp.exposure_layers.network import forwarding_ports
from cartography.intel.gcp.exposure_layers.network import GFE_RANGES
from cartography.intel.gcp.exposure_layers.network import HTTPS
from cartography.intel.gcp.exposure_layers.network import Instance
from cartography.intel.gcp.exposure_layers.network import is_proxy
from cartography.intel.gcp.exposure_layers.network import nic_blocker
from cartography.intel.gcp.exposure_layers.network import nic_hops
from cartography.intel.gcp.exposure_layers.network import PROJECT
from cartography.intel.gcp.exposure_layers.network import unresolved
from cartography.intel.gcp.exposure_layers.network import V4
from cartography.intel.gcp.exposure_layers.network import V6
from cartography.intel.gcp.exposure_layers.network import vpc_open
from cartography.intel.gcp.exposure_layers.network import VpcFacts
from cartography.intel.gcp.exposure_layers.network import WORLD_CIDR

Results = Dict[str, Dict[str, Reach]]  # label -> node id -> Reach
# service id -> (backend service path, LB hops); None: no NEG ingested
ServerlessLb = Optional[Dict[str, List[Tuple[Dict, List[Dict]]]]]

EXTERNAL_SCHEMES = ("EXTERNAL", "EXTERNAL_MANAGED")
FUNCTION_INGRESS_ALL = "ALLOW_ALL"
FUNCTION_INGRESS_LB = "ALLOW_INTERNAL_AND_GCLB"
FUNCTION_GEN_2 = "GEN_2"
RUN_INGRESS_ALL = "all"
RUN_INGRESS_LB = "internal-and-cloud-load-balancing"
VIA_LB_UNRESOLVED = "load_balancer_unresolved"
# exposure_paths[].entry.type: what the internet connects to first.
ENTRY_EXTERNAL_IP = "external_ip"
ENTRY_FORWARDING_RULE = "forwarding_rule"
ENTRY_URL = "url"
ENTRY_API_ENDPOINT = "api_endpoint"
GCS_HOST, BIGQUERY_HOST = "storage.googleapis.com", "bigquery.googleapis.com"


def entry(kind: str, entry_id: Optional[str], **extra: object) -> Dict:
    return {"type": kind, "id": entry_id, **extra}


def port_set(port: Optional[int]) -> Optional[PortSet]:
    return PortSet.of(TCP, port, port) if port is not None else None


def named_port(named_ports: List[str], port_name: Optional[str]) -> Optional[PortSet]:
    """Backend port from the group's "name:port" list; None when unknown (do not narrow)."""
    for entry in named_ports:
        name, _, port = entry.rpartition(":")
        if port_name and name == port_name and port.isdigit():
            return port_set(int(port))
    return None


# ---------------------------------------------------------------- instances (direct)


def instance_direct(inst: Instance, vpcs: Dict[str, VpcFacts]) -> Reach:
    reach = Reach()
    for family, has, reason in ((V4, inst.public_v4, "external_ip"), (V6, inst.public_v6, "external_ipv6")):
        if not has:
            continue
        reach.public_reasons.add(reason)
        if inst.running:
            _add_direct_paths(reach, inst, vpcs, family)
    return reach


def _add_direct_paths(reach: Reach, inst: Instance, vpcs: Dict[str, VpcFacts], family: str) -> None:
    """One path per network that admits the world; a blocker for each visible network that does not."""
    world = [WORLD_CIDR[family]]
    via = f"direct_ip{family}" + ("_unresolved_firewall" if unresolved(inst, vpcs) else "")
    ip = inst.external_ipv4 if family == V4 else inst.external_ipv6
    for vpc_id in inst.vpcs:
        vpc = vpcs.get(vpc_id)
        ports = vpc_open(inst, vpc, world, family)
        if not ports.is_empty():
            hops = nic_hops(inst, vpc_id, vpc, world, ports, family)
            reach.add_path(ports, via, hops=hops, entry=entry(ENTRY_EXTERNAL_IP, ip))
        elif vpc is not None:
            reach.block(**nic_blocker(inst, vpc_id, vpc, family))


# ---------------------------------------------------------------- load balancers


@dataclass
class LbFacts:
    url_maps: Dict[str, List[str]]   # url map partial uri -> backend refs
    backends: Dict[str, Dict]        # backend service id -> {groups, port_name}
    named_ports: Dict[str, List[str]]  # instance group id -> ["http:80"]
    members: Dict[str, List[str]]    # instance group uri -> instance ids (managed groups)


def listener_hop(row: Dict) -> Dict:
    """The forwarding rule as a hop; rule is its configured front-end port range (none: every port)."""
    return hop(HOP_LISTENER, row["id"], rule=row.get("port_range") or ",".join(row.get("ports") or []))


def forwarding_rules(rows: List[Dict]) -> Dict[str, Reach]:
    out = {}
    for row in rows:
        reach = Reach()
        if row.get("scheme") in EXTERNAL_SCHEMES:
            reach.public_reasons.add("external_forwarding_rule")
            front = forwarding_ports(row.get("protocol"), row.get("port_range"), row.get("ports"))
            reach.add_path(
                front, "external_ip", hops=[listener_hop(row)], entry=entry(ENTRY_EXTERNAL_IP, row.get("ip_address")),
            )
        out[row["id"]] = reach
    return out


def backend_path(
    inst: Optional[Instance], vpcs: Dict[str, VpcFacts], proxy: bool, ports: PortSet,
) -> Tuple[PortSet, List[Dict]]:
    """
    Ports of one backend instance an external rule reaches, and the network hops admitting them.
    Proxy LBs connect from the Google front ends, so the firewall must admit GFE_RANGES; passthrough
    LBs keep the client address, so it must admit the world. `ports` is the backend port (proxy) or
    the front-end port.

    ponytail: regional external Application LBs connect from the proxy-only subnet, not the GFE
    ranges; those backends read as unreachable until proxy-only subnets are ingested.
    """
    opened = PortSet.empty()
    hops: List[Dict] = []
    if inst is None or not inst.running:
        return opened, hops
    sources = list(GFE_RANGES if proxy else (WORLD_CIDR[V4],))
    for vpc_id in inst.vpcs:
        nic = vpc_open(inst, vpcs.get(vpc_id), sources) & ports
        if not nic.is_empty():
            opened = opened | nic
            hops.extend(nic_hops(inst, vpc_id, vpcs.get(vpc_id), sources, nic))
    return opened, hops


def _rule_backends(row: Dict, lb: LbFacts) -> List[str]:
    """Backend services of this project an external rule reaches, directly or via its URL map."""
    refs = list(row.get("backend_services") or []) + lb.url_maps.get(row.get("url_map") or "", [])
    return [bs_id for bs_id in dict.fromkeys(refs) if bs_id in lb.backends]


def _group_targets(backend: Dict, lb: LbFacts, proxy: bool, front: PortSet) -> List[Tuple[str, PortSet, str]]:
    """
    (instance id, port, instance group) behind one backend service. ponytail: unmanaged instance
    group members are not ingested (needs instanceGroups.listInstances per group); only managed groups resolve.
    """
    out: List[Tuple[str, PortSet, str]] = []
    for group in backend["groups"]:
        backend_port = named_port(lb.named_ports.get(group, []), backend["port_name"])
        ports = (backend_port or PortSet.everything()) if proxy else front
        out.extend((inst_id, ports, group) for inst_id in lb.members.get(group, []))
    return out


Target = Tuple[str, PortSet, bool, List[Dict]]  # instance id, port, via proxy, LB hops before the instance


def _lb_targets(row: Dict, lb: LbFacts, front: PortSet) -> List[Target]:
    """Backend instances of one external rule: target pool members, then backend service group members."""
    proxy = is_proxy(row.get("target"))
    # Target pools are passthrough: client address and front-end port reach the instance.
    pool = [hop(HOP_TARGET_GROUP, row.get("target"))]
    targets: List[Target] = [(i, front, False, pool) for i in row.get("target_instances") or []]
    for bs_id in _rule_backends(row, lb):
        for inst_id, ports, group in _group_targets(lb.backends[bs_id], lb, proxy, front):
            targets.append((inst_id, ports, proxy, [hop(HOP_BACKEND, bs_id), hop(HOP_TARGET_GROUP, group)]))
    return targets


def add_lb_paths(
    rows: List[Dict], rules: Dict[str, Reach], lb: LbFacts, instances: Dict[str, Instance],
    vpcs: Dict[str, VpcFacts], backends: Dict[str, Reach], inst_reach: Dict[str, Reach],
) -> None:
    """Propagate every external rule's reach to its backend services and backend instances."""
    for row in rows:
        front = rules[row["id"]].ports
        if front.is_empty():
            continue
        via, listener = f"forwarding_rule:{row['id']}", listener_hop(row)
        lb_entry = entry(ENTRY_FORWARDING_RULE, row["id"], listener_ports=front.to_strings())
        for bs_id in _rule_backends(row, lb):
            backends[bs_id].add_path(front, via, hops=[listener], entry=lb_entry)
        for inst_id, ports, via_proxy, lb_hops in _lb_targets(row, lb, front):
            if inst_id not in inst_reach:
                continue
            opened, nic = backend_path(instances.get(inst_id), vpcs, via_proxy, ports)
            inst_reach[inst_id].add_path(opened, via, hops=[listener, *lb_hops, *nic], entry=lb_entry)


# ---------------------------------------------------------------- managed services


def gke_clusters(rows: List[Dict]) -> Dict[str, Reach]:
    out = {}
    for row in rows:
        reach = Reach()
        if not row.get("private_endpoint") and row.get("endpoint"):
            reach.public_reasons.add("public_endpoint")
            _add_service_path(
                reach, row["id"], HTTPS, "public_endpoint", entry(ENTRY_EXTERNAL_IP, row["endpoint"]),
                _gke_admits(row), "master_authorized_networks",
            )
        out[row["id"]] = reach
    return out


def _gke_admits(row: Dict) -> Optional[str]:
    if not row.get("authorized_networks"):
        return "master_authorized_networks disabled"
    world = [c for c in row.get("cidrs") or [] if is_world(c)]
    return f"master_authorized_networks {world[0]}" if world else None


def _add_service_path(
    reach: Reach, node_id: str, ports: PortSet, via: str, path_entry: Dict, admits: Optional[str], setting: str,
) -> None:
    """Managed service: one path when its own setting (`admits` says how) lets the world in, else a blocker."""
    if admits:
        reach.add_path(ports, via, hops=[hop(HOP_SERVICE, node_id, rule=admits)], entry=path_entry)
    else:
        reach.block(HOP_SERVICE, node_id, BLOCK_NOT_ALLOWED, detail=setting)


def sql_instances(rows: List[Dict]) -> Dict[str, Reach]:
    out = {}
    for row in rows:
        reach = Reach()
        if row.get("ipv4") and row.get("public_ip"):
            reach.public_reasons.add("public_ip")
            world = [n for n in row.get("networks") or [] if is_world(n)]
            _add_service_path(
                reach, row["id"], port_set(row.get("port")) or PortSet.of(TCP), "authorized_networks",
                entry(ENTRY_EXTERNAL_IP, row["public_ip"]), f"authorized_networks {world[0]}" if world else None,
                "authorized_networks",
            )
        out[row["id"]] = reach
    return out


def serverless_lb_paths(negs: List[Dict], lb: LbFacts, backends: Dict[str, Reach]) -> ServerlessLb:
    """
    Function / Cloud Run service id -> (backend service path, hops to the NEG) for every reachable
    backend service whose serverless NEG names it. None when the project has no NEG node: the load
    balancer sync did not run (or found nothing), so a service admitting load balancers is unresolved.

    ponytail: a URL-mask NEG names no service and resolves to nothing; resolving the mask needs the
    services' URLs matched against it.
    """
    if not negs:
        return None
    targets = {n["id"]: n["function"] or n["run"] for n in negs}
    out: Dict[str, List[Tuple[Dict, List[Dict]]]] = {}
    for bs_id, bs_reach in backends.items():
        for group in lb.backends[bs_id]["groups"]:
            target = targets.get(group)
            if not target:
                continue
            lb_hops = [hop(HOP_BACKEND, bs_id), hop(HOP_TARGET_GROUP, group)]
            out.setdefault(target, []).extend((path, lb_hops) for path in bs_reach.paths.values())
    return out


def _add_serverless_paths(
    reach: Reach, node_id: str, url: Optional[str], via: str, ingress: str, open_ingress: str, lb_ingress: str,
    lb_paths: ServerlessLb,
) -> None:
    """
    Ingress `open_ingress`: the URL and any external load balancer reach it. `lb_ingress`: only an
    external load balancer, through a serverless NEG naming it; with no NEG ingested that cannot be
    told, so it stays reachable (unresolved), as the legacy function job does. Anything else: blocked.
    """
    service = hop(HOP_SERVICE, node_id, rule=f"ingress {ingress}")
    if ingress == open_ingress:
        reach.add_path(HTTPS, via, hops=[service], entry=entry(ENTRY_URL, url))
    if ingress in (open_ingress, lb_ingress):
        for path, lb_hops in (lb_paths or {}).get(node_id, []):
            reach.add_path(path["ports"], path["via"], hops=[*path["hops"], *lb_hops, service], entry=path["entry"])
    if ingress == lb_ingress and lb_paths is None:
        reach.add_path(HTTPS, VIA_LB_UNRESOLVED, hops=[service], entry=entry(ENTRY_URL, url))
    if not reach.via:
        reach.block(HOP_SERVICE, node_id, BLOCK_NOT_ALLOWED, detail="ingress")


def functions(rows: List[Dict], lb_paths: ServerlessLb) -> Dict[str, Reach]:
    """HTTP functions; a row with neither trigger field comes from an older sync and counts as HTTP."""
    out = {}
    for row in rows:
        reach = Reach()
        http = row.get("url") or row.get("environment") == FUNCTION_GEN_2 or not row.get("event_trigger")
        if http:
            reach.public_reasons.add("https_trigger")
            _add_serverless_paths(
                reach, row["id"], row.get("url"), "function_url", row.get("ingress") or FUNCTION_INGRESS_ALL,
                FUNCTION_INGRESS_ALL, FUNCTION_INGRESS_LB, lb_paths,
            )
        out[row["id"]] = reach
    return out


def cloud_run_services(rows: List[Dict], lb_paths: ServerlessLb) -> Dict[str, Reach]:
    out = {}
    for row in rows:
        reach = Reach()
        if row.get("url"):
            reach.public_reasons.add("run_url")
            _add_serverless_paths(
                reach, row["id"], row["url"], "run_url", row.get("ingress") or RUN_INGRESS_ALL,
                RUN_INGRESS_ALL, RUN_INGRESS_LB, lb_paths,
            )
        out[row["id"]] = reach
    return out


def google_api(ids: List[str], access: Dict[str, Dict], via: str, reason: str, host: str) -> Dict[str, Reach]:
    """Storage-style services: the API endpoint always answers; public when L3 says anonymous."""
    out = {}
    for node_id in ids:
        reach = Reach()
        if access.get(node_id, {}).get(ACCESS_AUTH) == AUTH_NONE:
            reach.public_reasons.add(reason)
        reach.add_path(HTTPS, via, entry=entry(ENTRY_API_ENDPOINT, host))
        out[node_id] = reach
    return out


# ---------------------------------------------------------------- graph reads


def _q(label: str, returns: str) -> str:
    return f"MATCH {PROJECT}-[:RESOURCE]->(n:{label}) RETURN n.id AS id, {returns}"


_FR_QUERY = _q(
    "GCPForwardingRule",
    "n.load_balancing_scheme AS scheme, n.ip_protocol AS protocol, n.port_range AS port_range, n.ports AS ports, "
    "n.target AS target, n.url_map AS url_map, n.backend_services AS backend_services, "
    "n.target_instances AS target_instances, n.ip_address AS ip_address",
)
_URL_MAP_QUERY = f"""
MATCH {PROJECT}-[:RESOURCE]->(n:GCPUrlMap) WHERE n.partial_uri IS NOT NULL
RETURN n.partial_uri AS id, coalesce(n.services, []) AS services
"""
_BACKEND_QUERY = _q("GCPBackendService", "coalesce(n.backend_groups, []) AS groups, n.port_name AS port_name")
_GROUP_QUERY = f"""
MATCH {PROJECT}-[:RESOURCE]->(n:GCPInstanceGroup)
OPTIONAL MATCH (i:GCPInstance)-[:PART_OF]->(n)
RETURN n.id AS id, n.instance_group AS group, coalesce(n.named_ports, []) AS named_ports, collect(i.id) AS members
"""
_GKE_QUERY = _q(
    "GKECluster",
    "n.endpoint AS endpoint, coalesce(n.private_endpoint_enabled, false) AS private_endpoint, "
    "coalesce(n.master_authorized_networks, false) AS authorized_networks, n.master_authorized_cidr_blocks AS cidrs",
)
_SQL_QUERY = _q(
    "GCPSQLInstance",
    "coalesce(n.ipV4Enabled, false) AS ipv4, n.public_ip AS public_ip, n.authorized_networks AS networks, "
    "n.port AS port",
)
_FUNCTION_QUERY = _q(
    "GCPFunction",
    "n.https_trigger_url AS url, n.environment AS environment, n.event_trigger_type AS event_trigger, "
    "n.ingressSettings AS ingress",
)
_RUN_QUERY = _q("GCPCloudRunService", "n.url AS url, n.ingress AS ingress")
# Serverless target of each NEG: the function loadbalancer.py linked, or the Cloud Run service id
# (cloudrun.py: projects/<p>/locations/<region>/services/<name>).
_NEG_QUERY = f"""
MATCH {PROJECT}-[:RESOURCE]->(n:GCPNetworkEndpointGroup)
OPTIONAL MATCH (n)-[:SERVERLESS_TARGET]->(fn:GCPFunction)
RETURN n.id AS id, fn.id AS function,
    CASE WHEN n.cloud_run_service IS NULL THEN null
    ELSE 'projects/' + $GCP_PROJECT_ID + '/locations/' + n.region + '/services/' + n.cloud_run_service END AS run
"""
_BUCKET_QUERY = f"MATCH {PROJECT}-[:RESOURCE]->(n:GCPBucket) RETURN n.id AS id"
_DATASET_QUERY = f"MATCH {PROJECT}-[:RESOURCE]->(n:GCPBigqueryDataset) RETURN n.id AS id"


def read_lb_facts(session: neo4j.Session, params: Dict) -> LbFacts:
    groups = [dict(r) for r in session.run(_GROUP_QUERY, **params)]
    members: Dict[str, List[str]] = {}
    for g in groups:
        members.setdefault(g["group"] or g["id"], []).extend(g["members"])
    return LbFacts(
        url_maps={r["id"]: r["services"] for r in session.run(_URL_MAP_QUERY, **params)},
        backends={r["id"]: dict(r) for r in session.run(_BACKEND_QUERY, **params)},
        named_ports={g["id"]: g["named_ports"] for g in groups},
        members=members,
    )


def compute(
    session: neo4j.Session, params: Dict, vpcs: Dict[str, VpcFacts], instances: Dict[str, Instance],
    access: Dict[str, Dict[str, Dict]],
) -> Results:
    """All GCP L1/L2 results for one project. `access` (L3) marks buckets / datasets public."""
    def q(query: str) -> List[Dict]:
        return [dict(r) for r in session.run(query, **params)]

    fr_rows = q(_FR_QUERY)
    rules = forwarding_rules(fr_rows)
    lb = read_lb_facts(session, params)
    backends = {bs_id: Reach() for bs_id in lb.backends}
    inst_reach = {i.id: instance_direct(i, vpcs) for i in instances.values()}
    add_lb_paths(fr_rows, rules, lb, instances, vpcs, backends, inst_reach)
    serverless = serverless_lb_paths(q(_NEG_QUERY), lb, backends)
    return {
        "GCPInstance": inst_reach,
        "GCPForwardingRule": rules,
        "GCPBackendService": backends,
        "GKECluster": gke_clusters(q(_GKE_QUERY)),
        "GCPSQLInstance": sql_instances(q(_SQL_QUERY)),
        "GCPFunction": functions(q(_FUNCTION_QUERY), serverless),
        "GCPCloudRunService": cloud_run_services(q(_RUN_QUERY), serverless),
        "GCPBucket": google_api(
            [r["id"] for r in q(_BUCKET_QUERY)], access.get("GCPBucket", {}), "gcs_endpoint", "public_iam_or_acl",
            GCS_HOST,
        ),
        "GCPBigqueryDataset": google_api(
            [r["id"] for r in q(_DATASET_QUERY)], access.get("GCPBigqueryDataset", {}), "bigquery_endpoint",
            "public_dataset_acl", BIGQUERY_HOST,
        ),
    }
