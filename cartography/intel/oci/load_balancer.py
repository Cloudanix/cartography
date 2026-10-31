# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI Load Balancer and Network Load Balancer API-centric functions.
# https://docs.oracle.com/en-us/iaas/Content/Balance/Concepts/balanceoverview.htm
# https://docs.oracle.com/en-us/iaas/Content/NetworkLoadBalancer/overview.htm
import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j
import oci

from . import tags
from . import utils
from cartography.client.core.tx import load_graph_data

logger = logging.getLogger(__name__)

LOAD_BALANCER_LABEL = 'OCILoadBalancer'
NETWORK_LOAD_BALANCER_LABEL = 'OCINetworkLoadBalancer'
ACTIVE = 'ACTIVE'

# Listener targets are '<protocol>:<port>' strings the exposure job matches against the
# '<protocol>:<min>-<max>' internet ingress ranges of security lists and NSG rules.
TCP = '6'
UDP = '17'
ANY_PROTOCOL = 'any'
# A Network Load Balancer listener on port 0 accepts every port.
ANY_PORT = 0
NLB_LISTENER_PROTOCOLS = {
    'TCP': [TCP],
    'UDP': [UDP],
    'TCP_AND_UDP': [TCP, UDP],
    'ANY': [ANY_PROTOCOL],
    'L3IP': [ANY_PROTOCOL],
}


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def get_load_balancer_list_data(
    lb_client: oci.load_balancer.LoadBalancerClient,
    compartment_id: str,
) -> List[Dict[str, Any]]:
    """
    List active load balancers in a compartment. The list response carries the full
    LoadBalancer (listeners, backend sets, IPs, subnets, NSGs), so no Get call is needed.
    See https://docs.oracle.com/en-us/iaas/api/#/en/loadbalancer/latest/LoadBalancer/ListLoadBalancers
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            lb_client.list_load_balancers, compartment_id=compartment_id, lifecycle_state=ACTIVE,
        )
        return utils.oci_object_to_json(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning("Could not retrieve load balancers for compartment '%s': %s", compartment_id, e.message)
        return []


def get_network_load_balancer_list_data(
    nlb_client: oci.network_load_balancer.NetworkLoadBalancerClient,
    compartment_id: str,
) -> List[Dict[str, Any]]:
    """
    List active network load balancers in a compartment. The summaries carry listeners,
    backend sets (with backends), IPs, subnet and NSGs.
    API: ListNetworkLoadBalancers, https://docs.oracle.com/en-us/iaas/api/#/en/networkloadbalancer/
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            nlb_client.list_network_load_balancers, compartment_id=compartment_id, lifecycle_state=ACTIVE,
        )
        return utils.oci_object_to_json(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve network load balancers for compartment '%s': %s", compartment_id, e.message,
        )
        return []


# ---------------------------------------------------------------------------
# Transform
# ---------------------------------------------------------------------------

def _backends(lb: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        backend
        for backend_set in (lb.get("backend-sets") or {}).values()
        for backend in (backend_set or {}).get("backends") or []
    ]


def _common_fields(lb: Dict[str, Any], region: str) -> Dict[str, Any]:
    ip_addresses = lb.get("ip-addresses") or []
    backends = _backends(lb)
    return {
        "id": lb.get("id"),
        "ocid": lb.get("id"),
        "display_name": lb.get("display-name"),
        "compartment_id": lb.get("compartment-id"),
        "lifecycle_state": lb.get("lifecycle-state"),
        "is_private": lb.get("is-private"),
        "ip_addresses": [ip["ip-address"] for ip in ip_addresses if ip.get("ip-address")],
        "public_ip_addresses": [
            ip["ip-address"] for ip in ip_addresses if ip.get("ip-address") and ip.get("is-public")
        ],
        "nsg_ids": lb.get("network-security-group-ids") or [],
        "backend_ips": sorted({b["ip-address"] for b in backends if b.get("ip-address")}),
        "time_created": str(lb.get("time-created", "")),
        "region": region,
    }


def transform_load_balancers(load_balancers: List[Dict[str, Any]], region: str) -> List[Dict[str, Any]]:
    """
    Shape LoadBalancer payloads for load_load_balancers. Every Load Balancer listener
    protocol (HTTP, HTTP2, TCP, GRPC) runs over TCP. Backends are addressed by IP only.
    """
    rows: List[Dict[str, Any]] = []
    for lb in load_balancers:
        if not lb.get("id"):
            continue
        ports = sorted({listener["port"] for listener in (lb.get("listeners") or {}).values() if listener.get("port")})
        rows.append({
            **_common_fields(lb, region),
            "shape": lb.get("shape-name"),
            "subnet_ids": lb.get("subnet-ids") or [],
            "listener_ports": ports,
            "listener_targets": [f"{TCP}:{port}" for port in ports],
            "backend_target_ids": [],
            "consolelink": utils.get_console_link("load_balancer", region=region, ocid=lb["id"]),
        })
    return rows


def transform_network_load_balancers(nlbs: List[Dict[str, Any]], region: str) -> List[Dict[str, Any]]:
    """
    Shape NetworkLoadBalancer payloads for load_load_balancers. A listener maps to one
    target per protocol it carries ('6:443', '17:53'); port 0 means every port, and ANY /
    L3IP listeners forward every protocol. Backends name an instance (target_id) or an IP.
    """
    rows: List[Dict[str, Any]] = []
    for nlb in nlbs:
        if not nlb.get("id"):
            continue
        listeners = [listener for listener in (nlb.get("listeners") or {}).values() if listener]
        targets = sorted({
            f"{protocol}:{listener.get('port') or ANY_PORT}"
            for listener in listeners
            for protocol in NLB_LISTENER_PROTOCOLS.get(listener.get("protocol"), [ANY_PROTOCOL])
        })
        backends = _backends(nlb)
        rows.append({
            **_common_fields(nlb, region),
            "shape": None,
            "subnet_ids": [nlb["subnet-id"]] if nlb.get("subnet-id") else [],
            "listener_ports": sorted({listener.get("port") or ANY_PORT for listener in listeners}),
            "listener_targets": targets,
            "backend_target_ids": sorted({b["target-id"] for b in backends if b.get("target-id")}),
            "consolelink": utils.get_console_link("network_load_balancer", region=region, ocid=nlb["id"]),
        })
    return rows


# ---------------------------------------------------------------------------
# Load
# ---------------------------------------------------------------------------

def load_load_balancers(
    neo4j_session: neo4j.Session,
    rows: List[Dict[str, Any]],
    label: str,
    compartment_id: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCILoadBalancer or OCINetworkLoadBalancer nodes (label) and attach them to their
    compartment via RESOURCE. Subnets, NSGs and backends are kept as id/IP lists, which the
    exposure jobs resolve.
    """
    if label not in (LOAD_BALANCER_LABEL, NETWORK_LOAD_BALANCER_LABEL):
        raise ValueError(f"Unexpected load balancer label {label}")
    ingest = f"""
    UNWIND $DictList AS row
        MERGE (lb:{label}{{id: row.id}})
        ON CREATE SET lb.firstseen = timestamp(),
                      lb.createdate = row.time_created
        SET lb.ocid = row.ocid,
            lb.display_name = row.display_name,
            lb.compartment_id = row.compartment_id,
            lb.lifecycle_state = row.lifecycle_state,
            lb.shape = row.shape,
            lb.is_private = row.is_private,
            lb.ip_addresses = row.ip_addresses,
            lb.public_ip_addresses = row.public_ip_addresses,
            lb.subnet_ids = row.subnet_ids,
            lb.nsg_ids = row.nsg_ids,
            lb.listener_ports = row.listener_ports,
            lb.listener_targets = row.listener_targets,
            lb.backend_ips = row.backend_ips,
            lb.backend_target_ids = row.backend_target_ids,
            lb.region = row.region,
            lb.consolelink = row.consolelink,
            lb.lastupdated = $oci_update_tag
        WITH lb
        MATCH (cc:OCICompartment{{id: $COMPARTMENT_ID}})
        MERGE (cc)-[r:RESOURCE]->(lb)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    load_graph_data(neo4j_session, ingest, rows, COMPARTMENT_ID=compartment_id, oci_update_tag=oci_update_tag)


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------

def sync_load_balancers(
    neo4j_session: neo4j.Session,
    lb_client: oci.load_balancer.LoadBalancerClient,
    nlb_client: oci.network_load_balancer.NetworkLoadBalancerClient,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Fetch -> transform -> load the Load Balancers and Network Load Balancers of one
    compartment in one region (the clients are already pinned to it).
    """
    for label, raw, transform in (
        (LOAD_BALANCER_LABEL, get_load_balancer_list_data(lb_client, compartment_id), transform_load_balancers),
        (
            NETWORK_LOAD_BALANCER_LABEL,
            get_network_load_balancer_list_data(nlb_client, compartment_id),
            transform_network_load_balancers,
        ),
    ):
        rows = transform(raw, region)
        if not rows:
            continue
        load_load_balancers(neo4j_session, rows, label, compartment_id, oci_update_tag)
        tags.sync_tags(neo4j_session, raw, label, oci_update_tag, common_job_parameters)
