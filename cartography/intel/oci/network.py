# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI Network API-centric functions
# https://docs.cloud.oracle.com/en-us/iaas/Content/Network/Concepts/overview.htm
import json
import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j
import oci.logging

from . import utils
from cartography.client.core.tx import load_graph_data
from cartography.util import run_cleanup_job

logger = logging.getLogger(__name__)


# ============================================================
# VCNs (Virtual Cloud Networks)
# ============================================================

def get_vcn_list_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all VCNs in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/Vcn/ListVcns
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            network_client.list_vcns, compartment_id=compartment_id,
        )
        return {'Vcns': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve VCNs for compartment '%s': %s", compartment_id, e.message,
        )
        return {'Vcns': []}


def load_vcns(
    neo4j_session: neo4j.Session,
    vcns: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI VCN data into Neo4j.
    """
    ingest_vcn = """
    UNWIND $DictList AS vcn
        MERGE (v:OCIVcn{id: vcn.ocid})
        ON CREATE SET v.firstseen = timestamp(),
        v.createdate = vcn.time_created
        SET v.ocid = vcn.ocid,
        v.display_name = vcn.display_name,
        v.compartment_id = vcn.compartment_id,
        v.resource_type = 'oci-vcn',
        v.cidr_block = vcn.cidr_block,
        v.dns_label = vcn.dns_label,
        v.lifecycle_state = vcn.lifecycle_state,
        v.region = $REGION,
        v.lastupdated = $oci_update_tag
        WITH v, vcn
        MATCH (cc:OCICompartment{id: vcn.compartment_id})
        MERGE (cc)-[r:RESOURCE]->(v)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": vcn.get("id"),
            "display_name": vcn.get("display-name"),
            "compartment_id": vcn.get("compartment-id", compartment_id),
            "cidr_block": vcn.get("cidr-block", ""),
            "dns_label": vcn.get("dns-label", ""),
            "lifecycle_state": vcn.get("lifecycle-state"),
            "time_created": str(vcn.get("time-created", "")),
        }
        for vcn in vcns
    ]
    load_graph_data(
        neo4j_session, ingest_vcn, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_vcns(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all VCNs across compartments.
    """
    logger.debug("Syncing OCI VCNs for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_vcn_list_data(network_client, compartment["ocid"])
        if data["Vcns"]:
            load_vcns(neo4j_session, data["Vcns"], tenancy_id, compartment["ocid"], region, oci_update_tag)


# ============================================================
# Subnets
# ============================================================

def get_subnet_list_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all subnets in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/Subnet/ListSubnets
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            network_client.list_subnets, compartment_id=compartment_id,
        )
        return {'Subnets': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve subnets for compartment '%s': %s", compartment_id, e.message,
        )
        return {'Subnets': []}


def load_subnets(
    neo4j_session: neo4j.Session,
    subnets: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Subnet data into Neo4j and link to VCN.
    """
    ingest_subnet = """
    UNWIND $DictList AS subnet
        MERGE (s:OCISubnet{id: subnet.ocid})
        ON CREATE SET s.firstseen = timestamp(),
        s.createdate = subnet.time_created
        SET s.ocid = subnet.ocid,
        s.display_name = subnet.display_name,
        s.compartment_id = subnet.compartment_id,
        s.resource_type = 'oci-subnet',
        s.cidr_block = subnet.cidr_block,
        s.availability_domain = subnet.availability_domain,
        s.dns_label = subnet.dns_label,
        s.lifecycle_state = subnet.lifecycle_state,
        s.vcn_id = subnet.vcn_id,
        s.route_table_id = subnet.route_table_id,
        s.security_list_ids = subnet.security_list_ids,
        s.subnet_domain_name = subnet.subnet_domain_name,
        s.prohibit_public_ip_on_vnic = subnet.prohibit_public_ip,
        s.region = $REGION,
        s.lastupdated = $oci_update_tag
        WITH s, subnet
        MATCH (vcn:OCIVcn{id: subnet.vcn_id})
        MERGE (vcn)-[r:OCI_SUBNET]->(s)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": subnet.get("id"),
            "display_name": subnet.get("display-name"),
            "compartment_id": subnet.get("compartment-id", compartment_id),
            "cidr_block": subnet.get("cidr-block", ""),
            "availability_domain": subnet.get("availability-domain", ""),
            "dns_label": subnet.get("dns-label", ""),
            "lifecycle_state": subnet.get("lifecycle-state"),
            "vcn_id": subnet.get("vcn-id", ""),
            "route_table_id": subnet.get("route-table-id", ""),
            "security_list_ids": subnet.get("security-list-ids", []) or [],
            "subnet_domain_name": subnet.get("subnet-domain-name", ""),
            "prohibit_public_ip": subnet.get("prohibit-public-ip-on-vnic", False),
            "time_created": str(subnet.get("time-created", "")),
        }
        for subnet in subnets
    ]
    load_graph_data(
        neo4j_session, ingest_subnet, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_subnets(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all subnets across compartments.
    """
    logger.debug("Syncing OCI subnets for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_subnet_list_data(network_client, compartment["ocid"])
        if data["Subnets"]:
            load_subnets(neo4j_session, data["Subnets"], tenancy_id, compartment["ocid"], region, oci_update_tag)


# ============================================================
# Security Lists
# ============================================================

def get_security_list_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all security lists in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/SecurityList/ListSecurityLists
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            network_client.list_security_lists, compartment_id=compartment_id,
        )
        return {'SecurityLists': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve security lists for compartment '%s': %s", compartment_id, e.message,
        )
        return {'SecurityLists': []}


def load_security_lists(
    neo4j_session: neo4j.Session,
    security_lists: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Security List data into Neo4j and link to VCN.
    """
    ingest_security_list = """
    UNWIND $DictList AS sl
        MERGE (s:OCISecurityList{id: sl.ocid})
        ON CREATE SET s.firstseen = timestamp(),
        s.createdate = sl.time_created
        SET s.ocid = sl.ocid,
        s.display_name = sl.display_name,
        s.compartment_id = sl.compartment_id,
        s.resource_type = 'oci-security-list',
        s.vcn_id = sl.vcn_id,
        s.lifecycle_state = sl.lifecycle_state,
        s.ingress_security_rules = sl.ingress_rules,
        s.egress_security_rules = sl.egress_rules,
        s.region = $REGION,
        s.lastupdated = $oci_update_tag
        WITH s, sl
        MATCH (vcn:OCIVcn{id: sl.vcn_id})
        MERGE (vcn)-[r:OCI_SECURITY_LIST]->(s)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = []
    for sl in security_lists:
        ingress_rules = sl.get("ingress-security-rules", [])
        egress_rules = sl.get("egress-security-rules", [])
        rows.append({
            "ocid": sl.get("id"),
            "display_name": sl.get("display-name"),
            "compartment_id": sl.get("compartment-id", compartment_id),
            "vcn_id": sl.get("vcn-id", ""),
            "lifecycle_state": sl.get("lifecycle-state"),
            "ingress_rules": json.dumps(ingress_rules) if ingress_rules else "[]",
            "egress_rules": json.dumps(egress_rules) if egress_rules else "[]",
            "time_created": str(sl.get("time-created", "")),
        })
    load_graph_data(
        neo4j_session, ingest_security_list, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_security_lists(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all security lists across compartments.
    """
    logger.debug("Syncing OCI security lists for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_security_list_data(network_client, compartment["ocid"])
        if data["SecurityLists"]:
            load_security_lists(
                neo4j_session, data["SecurityLists"], tenancy_id, compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# Network Security Groups (NSGs)
# ============================================================

def get_network_security_group_list_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all Network Security Groups in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/ListNetworkSecurityGroups
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            network_client.list_network_security_groups, compartment_id=compartment_id,
        )
        return {'NetworkSecurityGroups': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve NSGs for compartment '%s': %s", compartment_id, e.message,
        )
        return {'NetworkSecurityGroups': []}


def load_network_security_groups(
    neo4j_session: neo4j.Session,
    nsgs: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Network Security Group data into Neo4j and link to VCN.
    """
    ingest_nsg = """
    UNWIND $DictList AS nsg
        MERGE (g:OCINetworkSecurityGroup{id: nsg.ocid})
        ON CREATE SET g.firstseen = timestamp(),
        g.createdate = nsg.time_created
        SET g.ocid = nsg.ocid,
        g.display_name = nsg.display_name,
        g.compartment_id = nsg.compartment_id,
        g.resource_type = 'oci-network-security-group',
        g.vcn_id = nsg.vcn_id,
        g.lifecycle_state = nsg.lifecycle_state,
        g.region = $REGION,
        g.lastupdated = $oci_update_tag
        WITH g, nsg
        MATCH (vcn:OCIVcn{id: nsg.vcn_id})
        MERGE (vcn)-[r:OCI_NETWORK_SECURITY_GROUP]->(g)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": nsg.get("id"),
            "display_name": nsg.get("display-name"),
            "compartment_id": nsg.get("compartment-id", compartment_id),
            "vcn_id": nsg.get("vcn-id", ""),
            "lifecycle_state": nsg.get("lifecycle-state"),
            "time_created": str(nsg.get("time-created", "")),
        }
        for nsg in nsgs
    ]
    load_graph_data(
        neo4j_session, ingest_nsg, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_network_security_groups(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all Network Security Groups across compartments.
    """
    logger.debug("Syncing OCI NSGs for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_network_security_group_list_data(network_client, compartment["ocid"])
        if data["NetworkSecurityGroups"]:
            load_network_security_groups(
                neo4j_session, data["NetworkSecurityGroups"], tenancy_id,
                compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# NSG Security Rules
# ============================================================

def get_nsg_security_rules_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    nsg_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all security rules for a given Network Security Group.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/SecurityRule/ListNetworkSecurityGroupSecurityRules
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            network_client.list_network_security_group_security_rules,
            nsg_id,
        )
        return {'SecurityRules': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve NSG security rules for NSG '%s': %s", nsg_id, e.message,
        )
        return {'SecurityRules': []}


def load_nsg_security_rules(
    neo4j_session: neo4j.Session,
    rules: List[Dict[str, Any]],
    nsg_id: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI NSG Security Rule data into Neo4j and link to NSG.
    """
    ingest_rule = """
    UNWIND $DictList AS rule
        MERGE (rl:OCINsgSecurityRule{id: rule.ocid})
        ON CREATE SET rl.firstseen = timestamp()
        SET rl.ocid = rule.ocid,
        rl.direction = rule.direction,
        rl.protocol = rule.protocol,
        rl.description = rule.description,
        rl.source = rule.source,
        rl.source_type = rule.source_type,
        rl.destination = rule.destination,
        rl.destination_type = rule.destination_type,
        rl.is_stateless = rule.is_stateless,
        rl.is_valid = rule.is_valid,
        rl.tcp_dest_port_min = rule.tcp_dest_port_min,
        rl.tcp_dest_port_max = rule.tcp_dest_port_max,
        rl.tcp_src_port_min = rule.tcp_src_port_min,
        rl.tcp_src_port_max = rule.tcp_src_port_max,
        rl.udp_dest_port_min = rule.udp_dest_port_min,
        rl.udp_dest_port_max = rule.udp_dest_port_max,
        rl.icmp_type = rule.icmp_type,
        rl.icmp_code = rule.icmp_code,
        rl.lastupdated = $oci_update_tag
        WITH rl
        MATCH (nsg:OCINetworkSecurityGroup{id: $NSG_ID})
        MERGE (nsg)-[r:OCI_NSG_RULE]->(rl)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = []
    for rule in rules:
        # Extract TCP options
        tcp_options = rule.get("tcp-options", {}) or {}
        tcp_dest_range = tcp_options.get("destination-port-range", {}) or {}
        tcp_src_range = tcp_options.get("source-port-range", {}) or {}

        # Extract UDP options
        udp_options = rule.get("udp-options", {}) or {}
        udp_dest_range = udp_options.get("destination-port-range", {}) or {}

        # Extract ICMP options
        icmp_options = rule.get("icmp-options", {}) or {}

        rows.append({
            "ocid": rule.get("id"),
            "direction": rule.get("direction", ""),
            "protocol": rule.get("protocol", ""),
            "description": rule.get("description", ""),
            "source": rule.get("source", ""),
            "source_type": rule.get("source-type", ""),
            "destination": rule.get("destination", ""),
            "destination_type": rule.get("destination-type", ""),
            "is_stateless": rule.get("is-stateless", False),
            "is_valid": rule.get("is-valid", True),
            "tcp_dest_port_min": tcp_dest_range.get("min"),
            "tcp_dest_port_max": tcp_dest_range.get("max"),
            "tcp_src_port_min": tcp_src_range.get("min"),
            "tcp_src_port_max": tcp_src_range.get("max"),
            "udp_dest_port_min": udp_dest_range.get("min"),
            "udp_dest_port_max": udp_dest_range.get("max"),
            "icmp_type": icmp_options.get("type"),
            "icmp_code": icmp_options.get("code"),
        })

    load_graph_data(
        neo4j_session, ingest_rule, rows,
        NSG_ID=nsg_id, oci_update_tag=oci_update_tag,
    )


def sync_nsg_security_rules(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all NSG security rules by querying existing NSGs from Neo4j
    and fetching rules for each.
    """
    logger.debug("Syncing OCI NSG security rules for tenancy '%s', region '%s'.", tenancy_id, region)
    compartment_ocid = common_job_parameters.get("OCI_COMPARTMENT_ID", tenancy_id)
    query = (
        "MATCH (:OCICompartment{id: $COMPARTMENT_ID})-[:RESOURCE]->(:OCIVcn)"
        "-[:OCI_NETWORK_SECURITY_GROUP]->(nsg:OCINetworkSecurityGroup) "
        "WHERE nsg.region = $REGION "
        "RETURN nsg.ocid as ocid"
    )
    nsgs = neo4j_session.run(query, COMPARTMENT_ID=compartment_ocid, REGION=region)
    for nsg in nsgs:
        data = get_nsg_security_rules_data(network_client, nsg["ocid"])
        if data["SecurityRules"]:
            load_nsg_security_rules(neo4j_session, data["SecurityRules"], nsg["ocid"], oci_update_tag)


# ============================================================
# Internet Gateways
# ============================================================

def get_internet_gateway_list_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all internet gateways in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/InternetGateway/ListInternetGateways
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            network_client.list_internet_gateways, compartment_id=compartment_id,
        )
        return {'InternetGateways': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve internet gateways for compartment '%s': %s", compartment_id, e.message,
        )
        return {'InternetGateways': []}


def load_internet_gateways(
    neo4j_session: neo4j.Session,
    gateways: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Internet Gateway data into Neo4j and link to VCN.
    """
    ingest_igw = """
    UNWIND $DictList AS gw
        MERGE (igw:OCIInternetGateway{id: gw.ocid})
        ON CREATE SET igw.firstseen = timestamp(),
        igw.createdate = gw.time_created
        SET igw.ocid = gw.ocid,
        igw.display_name = gw.display_name,
        igw.compartment_id = gw.compartment_id,
        igw.resource_type = 'oci-internet-gateway',
        igw.vcn_id = gw.vcn_id,
        igw.is_enabled = gw.is_enabled,
        igw.lifecycle_state = gw.lifecycle_state,
        igw.region = $REGION,
        igw.lastupdated = $oci_update_tag
        WITH igw, gw
        MATCH (vcn:OCIVcn{id: gw.vcn_id})
        MERGE (vcn)-[r:OCI_INTERNET_GATEWAY]->(igw)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": gw.get("id"),
            "display_name": gw.get("display-name"),
            "compartment_id": gw.get("compartment-id", compartment_id),
            "vcn_id": gw.get("vcn-id", ""),
            "is_enabled": gw.get("is-enabled", True),
            "lifecycle_state": gw.get("lifecycle-state"),
            "time_created": str(gw.get("time-created", "")),
        }
        for gw in gateways
    ]
    load_graph_data(
        neo4j_session, ingest_igw, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_internet_gateways(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all internet gateways across compartments.
    """
    logger.debug("Syncing OCI internet gateways for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_internet_gateway_list_data(network_client, compartment["ocid"])
        if data["InternetGateways"]:
            load_internet_gateways(
                neo4j_session, data["InternetGateways"], tenancy_id, compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# NAT Gateways
# ============================================================

def get_nat_gateway_list_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all NAT gateways in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/NatGateway/ListNatGateways
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            network_client.list_nat_gateways, compartment_id=compartment_id,
        )
        return {'NatGateways': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve NAT gateways for compartment '%s': %s", compartment_id, e.message,
        )
        return {'NatGateways': []}


def load_nat_gateways(
    neo4j_session: neo4j.Session,
    gateways: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI NAT Gateway data into Neo4j and link to VCN.
    """
    ingest_nat = """
    UNWIND $DictList AS gw
        MERGE (nat:OCINatGateway{id: gw.ocid})
        ON CREATE SET nat.firstseen = timestamp(),
        nat.createdate = gw.time_created
        SET nat.ocid = gw.ocid,
        nat.display_name = gw.display_name,
        nat.compartment_id = gw.compartment_id,
        nat.vcn_id = gw.vcn_id,
        nat.nat_ip = gw.nat_ip,
        nat.block_traffic = gw.block_traffic,
        nat.lifecycle_state = gw.lifecycle_state,
        nat.region = $REGION,
        nat.lastupdated = $oci_update_tag
        WITH nat, gw
        MATCH (vcn:OCIVcn{id: gw.vcn_id})
        MERGE (vcn)-[r:OCI_NAT_GATEWAY]->(nat)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": gw.get("id"),
            "display_name": gw.get("display-name"),
            "compartment_id": gw.get("compartment-id", compartment_id),
            "vcn_id": gw.get("vcn-id", ""),
            "nat_ip": gw.get("nat-ip", ""),
            "block_traffic": gw.get("block-traffic", False),
            "lifecycle_state": gw.get("lifecycle-state"),
            "time_created": str(gw.get("time-created", "")),
        }
        for gw in gateways
    ]
    load_graph_data(
        neo4j_session, ingest_nat, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_nat_gateways(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all NAT gateways across compartments.
    """
    logger.debug("Syncing OCI NAT gateways for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_nat_gateway_list_data(network_client, compartment["ocid"])
        if data["NatGateways"]:
            load_nat_gateways(
                neo4j_session, data["NatGateways"], tenancy_id, compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# Route Tables
# ============================================================

def get_route_table_list_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all route tables in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/RouteTable/ListRouteTables
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            network_client.list_route_tables, compartment_id=compartment_id,
        )
        return {'RouteTables': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve route tables for compartment '%s': %s", compartment_id, e.message,
        )
        return {'RouteTables': []}


def load_route_tables(
    neo4j_session: neo4j.Session,
    route_tables: List[Dict[str, Any]],
    tenancy_id: str,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI Route Table data into Neo4j and link to VCN.
    """
    ingest_rt = """
    UNWIND $DictList AS rt
        MERGE (t:OCIRouteTable{id: rt.ocid})
        ON CREATE SET t.firstseen = timestamp(),
        t.createdate = rt.time_created
        SET t.ocid = rt.ocid,
        t.display_name = rt.display_name,
        t.compartment_id = rt.compartment_id,
        t.resource_type = 'oci-route-table',
        t.vcn_id = rt.vcn_id,
        t.lifecycle_state = rt.lifecycle_state,
        t.route_rules = rt.route_rules,
        t.region = $REGION,
        t.lastupdated = $oci_update_tag
        WITH t, rt
        MATCH (vcn:OCIVcn{id: rt.vcn_id})
        MERGE (vcn)-[r:OCI_ROUTE_TABLE]->(t)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = []
    for rt in route_tables:
        route_rules = rt.get("route-rules", [])
        rows.append({
            "ocid": rt.get("id"),
            "display_name": rt.get("display-name"),
            "compartment_id": rt.get("compartment-id", compartment_id),
            "vcn_id": rt.get("vcn-id", ""),
            "lifecycle_state": rt.get("lifecycle-state"),
            "route_rules": json.dumps(route_rules) if route_rules else "[]",
            "time_created": str(rt.get("time-created", "")),
        })
    load_graph_data(
        neo4j_session, ingest_rt, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_route_tables(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync all route tables across compartments.
    """
    logger.debug("Syncing OCI route tables for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        data = get_route_table_list_data(network_client, compartment["ocid"])
        if data["RouteTables"]:
            load_route_tables(
                neo4j_session, data["RouteTables"], tenancy_id, compartment["ocid"], region, oci_update_tag,
            )


# ============================================================
# Subnet associations (Subnet -> RouteTable, Subnet -> SecurityList)
# ============================================================

def sync_subnet_associations(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Link subnets to the route tables and security lists they reference. The IDs are
    captured on the OCISubnet node by load_subnets (route_table_id, security_list_ids).
    """
    logger.debug("Syncing OCI subnet associations for tenancy '%s', region '%s'.", tenancy_id, region)
    link_subnet_route_table = """
    UNWIND $DictList AS row
        MATCH (subnet:OCISubnet{id: row.subnet_id})
        MATCH (rt:OCIRouteTable{id: row.route_table_id})
        MERGE (subnet)-[r:OCI_ROUTE_TABLE]->(rt)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    link_subnet_security_list = """
    UNWIND $DictList AS row
        MATCH (subnet:OCISubnet{id: row.subnet_id})
        MATCH (sl:OCISecurityList{id: row.security_list_id})
        MERGE (subnet)-[r:OCI_SECURITY_LIST]->(sl)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    query = (
        "MATCH (:OCICompartment{id: $COMPARTMENT_ID})-[:RESOURCE]->(:OCIVcn)"
        "-[:OCI_SUBNET]->(subnet:OCISubnet) "
        "WHERE subnet.region = $REGION "
        "RETURN subnet.ocid as ocid, subnet.route_table_id as route_table_id, "
        "subnet.security_list_ids as security_list_ids"
    )
    for compartment in compartments:
        subnets = neo4j_session.run(query, COMPARTMENT_ID=compartment["ocid"], REGION=region)
        rt_rows = []
        sl_rows = []
        for subnet in subnets:
            route_table_id = subnet["route_table_id"]
            if route_table_id:
                rt_rows.append({"subnet_id": subnet["ocid"], "route_table_id": route_table_id})
            for security_list_id in (subnet["security_list_ids"] or []):
                sl_rows.append({"subnet_id": subnet["ocid"], "security_list_id": security_list_id})
        load_graph_data(neo4j_session, link_subnet_route_table, rt_rows, oci_update_tag=oci_update_tag)
        load_graph_data(neo4j_session, link_subnet_security_list, sl_rows, oci_update_tag=oci_update_tag)


# ============================================================
# VNICs
# ============================================================

def get_vnic_data(
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    vnic_id: str,
) -> Dict[str, Any]:
    """
    Get a single VNIC's details.
    See https://docs.oracle.com/en-us/iaas/api/#/en/iaas/latest/Vnic/GetVnic
    """
    try:
        response = network_client.get_vnic(vnic_id)
        return utils.oci_single_object_to_json(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve VNIC '%s': %s", vnic_id, e.message,
        )
        return {}


def load_vnics(
    neo4j_session: neo4j.Session,
    vnics: List[Dict[str, Any]],
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI VNIC data into Neo4j, link to subnet, and link to the owning instance
    via its VNIC attachment.
    """
    ingest_vnic = """
    UNWIND $DictList AS vnic
        MERGE (v:OCIVnic{id: vnic.ocid})
        ON CREATE SET v.firstseen = timestamp(),
        v.createdate = vnic.time_created
        SET v.ocid = vnic.ocid,
        v.display_name = vnic.display_name,
        v.compartment_id = vnic.compartment_id,
        v.availability_domain = vnic.availability_domain,
        v.lifecycle_state = vnic.lifecycle_state,
        v.private_ip = vnic.private_ip,
        v.public_ip = vnic.public_ip,
        v.is_primary = vnic.is_primary,
        v.hostname_label = vnic.hostname_label,
        v.mac_address = vnic.mac_address,
        v.skip_source_dest_check = vnic.skip_source_dest_check,
        v.subnet_id = vnic.subnet_id,
        v.region = $REGION,
        v.lastupdated = $oci_update_tag
        WITH v, vnic
        OPTIONAL MATCH (subnet:OCISubnet{id: vnic.subnet_id})
        FOREACH (_ IN CASE WHEN subnet IS NULL THEN [] ELSE [1] END |
            MERGE (subnet)-[rs:OCI_VNIC]->(v)
            ON CREATE SET rs.firstseen = timestamp()
            SET rs.lastupdated = $oci_update_tag
        )
        WITH v, vnic
        OPTIONAL MATCH (attachment:OCIVnicAttachment{vnic_id: vnic.ocid})
        FOREACH (_ IN CASE WHEN attachment IS NULL THEN [] ELSE [1] END |
            MERGE (attachment)-[ra:OCI_VNIC]->(v)
            ON CREATE SET ra.firstseen = timestamp()
            SET ra.lastupdated = $oci_update_tag
        )
    """

    rows = [
        {
            "ocid": vnic.get("id"),
            "display_name": vnic.get("display-name"),
            "compartment_id": vnic.get("compartment-id", ""),
            "availability_domain": vnic.get("availability-domain", ""),
            "lifecycle_state": vnic.get("lifecycle-state"),
            "private_ip": vnic.get("private-ip", ""),
            "public_ip": vnic.get("public-ip", ""),
            "is_primary": vnic.get("is-primary", False),
            "hostname_label": vnic.get("hostname-label", ""),
            "mac_address": vnic.get("mac-address", ""),
            "skip_source_dest_check": vnic.get("skip-source-dest-check", False),
            "subnet_id": vnic.get("subnet-id", ""),
            "time_created": str(vnic.get("time-created", "")),
        }
        for vnic in vnics
    ]
    load_graph_data(
        neo4j_session, ingest_vnic, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_vnics(
    neo4j_session: neo4j.Session,
    network_client: oci.core.virtual_network_client.VirtualNetworkClient,
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync VNICs by reading the VNIC IDs recorded on OCIVnicAttachment nodes (populated by
    compute.sync) and fetching each VNIC's details from the Network API.
    """
    logger.debug("Syncing OCI VNICs for tenancy '%s', region '%s'.", tenancy_id, region)
    query = (
        "MATCH (:OCICompartment{id: $COMPARTMENT_ID})-[:RESOURCE]->(inst:OCIInstance)"
        "-[:OCI_VNIC_ATTACHMENT]->(attachment:OCIVnicAttachment) "
        "WHERE attachment.vnic_id IS NOT NULL AND inst.region = $REGION "
        "RETURN DISTINCT attachment.vnic_id as vnic_id"
    )
    for compartment in compartments:
        attachments = neo4j_session.run(query, COMPARTMENT_ID=compartment["ocid"], REGION=region)
        vnics = []
        for attachment in attachments:
            vnic = get_vnic_data(network_client, attachment["vnic_id"])
            if vnic:
                vnics.append(vnic)
        if vnics:
            load_vnics(neo4j_session, vnics, region, oci_update_tag)


# ============================================================
# Flow Logs (from the Logging service)
# ============================================================

def get_log_group_list_data(
    logging_client: "oci.logging.LoggingManagementClient",
    compartment_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all log groups in a compartment.
    See https://docs.oracle.com/en-us/iaas/api/#/en/logging-management/latest/LogGroup/ListLogGroups
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            logging_client.list_log_groups, compartment_id=compartment_id,
        )
        return {'LogGroups': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve log groups for compartment '%s': %s", compartment_id, e.message,
        )
        return {'LogGroups': []}


def get_log_list_data(
    logging_client: "oci.logging.LoggingManagementClient",
    log_group_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all logs within a log group.
    See https://docs.oracle.com/en-us/iaas/api/#/en/logging-management/latest/Log/ListLogs
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            logging_client.list_logs, log_group_id,
        )
        return {'Logs': utils.oci_object_to_json(response.data)}
    except oci.exceptions.ServiceError as e:
        logger.warning(
            "Could not retrieve logs for log group '%s': %s", log_group_id, e.message,
        )
        return {'Logs': []}


def load_flow_logs(
    neo4j_session: neo4j.Session,
    logs: List[Dict[str, Any]],
    log_group_id: str,
    region: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCI flow logs (VCN flow logs are service logs sourced from the
    flowlogs/vcn service) into Neo4j and link them to the subnet or VCN they
    are configured for.
    """
    ingest_flow_log = """
    UNWIND $DictList AS log
        MERGE (fl:OCIFlowLog:OCILog{id: log.ocid})
        ON CREATE SET fl.firstseen = timestamp(),
        fl.createdate = log.time_created
        SET fl.ocid = log.ocid,
        fl.display_name = log.display_name,
        fl.compartment_id = log.compartment_id,
        fl.log_group_id = log.log_group_id,
        fl.log_type = log.log_type,
        fl.is_enabled = log.is_enabled,
        fl.lifecycle_state = log.lifecycle_state,
        fl.source_service = log.source_service,
        fl.source_category = log.source_category,
        fl.source_resource = log.source_resource,
        fl.region = $REGION,
        fl.lastupdated = $oci_update_tag
        WITH fl, log.source_resource as source_resource
        OPTIONAL MATCH (subnet:OCISubnet{id: source_resource})
        FOREACH (_ IN CASE WHEN subnet IS NULL THEN [] ELSE [1] END |
            MERGE (subnet)-[rs:OCI_FLOW_LOG]->(fl)
            ON CREATE SET rs.firstseen = timestamp()
            SET rs.lastupdated = $oci_update_tag
        )
        WITH fl, source_resource
        OPTIONAL MATCH (vcn:OCIVcn{id: source_resource})
        FOREACH (_ IN CASE WHEN vcn IS NULL THEN [] ELSE [1] END |
            MERGE (vcn)-[rv:OCI_FLOW_LOG]->(fl)
            ON CREATE SET rv.firstseen = timestamp()
            SET rv.lastupdated = $oci_update_tag
        )
    """

    rows = []
    for log in logs:
        configuration = log.get("configuration", {}) or {}
        source = configuration.get("source", {}) or {}
        rows.append({
            "ocid": log.get("id"),
            "display_name": log.get("display-name"),
            "compartment_id": log.get("compartment-id", ""),
            "log_group_id": log.get("log-group-id", log_group_id),
            "log_type": log.get("log-type", ""),
            "is_enabled": log.get("is-enabled", False),
            "lifecycle_state": log.get("lifecycle-state"),
            "source_service": source.get("service", ""),
            "source_category": source.get("category", ""),
            "source_resource": source.get("resource", ""),
            "time_created": str(log.get("time-created", "")),
        })

    load_graph_data(
        neo4j_session, ingest_flow_log, rows,
        REGION=region, oci_update_tag=oci_update_tag,
    )


def sync_flow_logs(
    neo4j_session: neo4j.Session,
    logging_client: "oci.logging.LoggingManagementClient",
    compartments: List[Dict[str, Any]],
    tenancy_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Sync VCN flow logs across compartments. Flow logs are OCI service logs whose
    source service is "flowlogs". We enumerate log groups, then the logs within
    each group, and keep only the flow logs.
    """
    logger.debug("Syncing OCI flow logs for tenancy '%s', region '%s'.", tenancy_id, region)
    for compartment in compartments:
        log_groups = get_log_group_list_data(logging_client, compartment["ocid"])
        for log_group in log_groups["LogGroups"]:
            log_group_id = log_group.get("id")
            if not log_group_id:
                continue
            data = get_log_list_data(logging_client, log_group_id)
            flow_logs = [
                log for log in data["Logs"]
                if ((log.get("configuration", {}) or {}).get("source", {}) or {}).get("service") == "flowlogs"
            ]
            if flow_logs:
                load_flow_logs(neo4j_session, flow_logs, log_group_id, region, oci_update_tag)


# ============================================================
# Top-level sync function
# ============================================================

def sync(
    neo4j_session: neo4j.Session,
    network: oci.core.virtual_network_client.VirtualNetworkClient,
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
    regions: List[str] = None,
) -> None:
    """
    Sync OCI Network resources for the compartment specified in common_job_parameters.
    """
    compartment_ocid = common_job_parameters.get("OCI_COMPARTMENT_ID", tenancy_id)
    logger.info("Syncing OCI Network for compartment '%s'.", compartment_ocid)

    # Use only the target compartment for resource listing
    compartments = [{"ocid": compartment_ocid, "name": "target", "compartmentid": tenancy_id}]

    # If no regions provided, use the network client's current region
    if not regions:
        regions = [network.base_client.region or ""]

    # The Logging service (separate client) provides VCN flow logs. Reuse the
    # network client's config/signer so we authenticate identically.
    logging_client = oci.logging.LoggingManagementClient(
        config=network.base_client.config,
        signer=getattr(network.base_client, "signer", None),
    )

    for region in regions:
        logger.info("Syncing OCI Network in region '%s' for compartment '%s'.", region, compartment_ocid)
        network.base_client.set_region(region)
        logging_client.base_client.set_region(region)

        # Sync VCNs first (parent of all other network resources)
        sync_vcns(neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters)

        # Sync subnets (children of VCNs)
        sync_subnets(neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters)

        # Sync security lists (children of VCNs)
        sync_security_lists(
            neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

        # Sync Network Security Groups (children of VCNs)
        sync_network_security_groups(
            neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

        # Sync NSG security rules (children of NSGs)
        sync_nsg_security_rules(
            neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

        # Sync internet gateways (children of VCNs)
        sync_internet_gateways(
            neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

        # Sync NAT gateways (children of VCNs)
        sync_nat_gateways(
            neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

        # Sync route tables (children of VCNs)
        sync_route_tables(
            neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

        # Link subnets to their route tables and security lists (needs route tables
        # and security lists to already exist).
        sync_subnet_associations(
            neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

        # Sync VNICs (needs OCIVnicAttachment nodes from compute.sync and subnets).
        sync_vnics(
            neo4j_session, network, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

        # Sync VCN flow logs (from the Logging service; links to subnet/VCN).
        sync_flow_logs(
            neo4j_session, logging_client, compartments, tenancy_id, region, oci_update_tag, common_job_parameters,
        )

    # Cleanup stale network nodes
    run_cleanup_job('oci_import_network_cleanup.json', neo4j_session, common_job_parameters)
