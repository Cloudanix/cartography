# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI API Gateway API-centric functions.
# https://docs.oracle.com/en-us/iaas/Content/APIGateway/Concepts/apigatewayoverview.htm
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

ACTIVE = 'ACTIVE'


def get_gateway_list_data(
    gateway_client: oci.apigateway.GatewayClient,
    compartment_id: str,
) -> List[Dict[str, Any]]:
    """
    List active API gateways in a compartment. The summary carries the endpoint type,
    subnet and NSGs, which is all the exposure job needs.
    API: ListGateways, https://docs.oracle.com/en-us/iaas/api/#/en/api-gateway/
    """
    try:
        response = oci.pagination.list_call_get_all_results(
            gateway_client.list_gateways, compartment_id=compartment_id, lifecycle_state=ACTIVE,
        )
        return utils.oci_object_to_json(response.data)
    except oci.exceptions.ServiceError as e:
        logger.warning("Could not retrieve API gateways for compartment '%s': %s", compartment_id, e.message)
        return []


def transform_gateways(gateways: List[Dict[str, Any]], region: str) -> List[Dict[str, Any]]:
    return [
        {
            "id": gw["id"],
            "ocid": gw["id"],
            "display_name": gw.get("display-name"),
            "compartment_id": gw.get("compartment-id"),
            "lifecycle_state": gw.get("lifecycle-state"),
            # PUBLIC gateways get a public IP in their subnet; PRIVATE ones only a private IP.
            "endpoint_type": gw.get("endpoint-type"),
            "hostname": gw.get("hostname"),
            "subnet_id": gw.get("subnet-id"),
            "nsg_ids": gw.get("network-security-group-ids") or [],
            "time_created": str(gw.get("time-created", "")),
            "region": region,
            "consolelink": utils.get_console_link("api_gateway", region=region, ocid=gw["id"]),
        }
        for gw in gateways if gw.get("id")
    ]


def load_gateways(
    neo4j_session: neo4j.Session,
    gateways: List[Dict[str, Any]],
    compartment_id: str,
    oci_update_tag: int,
) -> None:
    """
    Ingest OCIApiGateway nodes and attach them to their compartment via RESOURCE.
    """
    ingest = """
    UNWIND $DictList AS row
        MERGE (gw:OCIApiGateway{id: row.id})
        ON CREATE SET gw.firstseen = timestamp(),
                      gw.createdate = row.time_created
        SET gw.ocid = row.ocid,
            gw.display_name = row.display_name,
            gw.compartment_id = row.compartment_id,
            gw.lifecycle_state = row.lifecycle_state,
            gw.endpoint_type = row.endpoint_type,
            gw.hostname = row.hostname,
            gw.subnet_id = row.subnet_id,
            gw.nsg_ids = row.nsg_ids,
            gw.region = row.region,
            gw.consolelink = row.consolelink,
            gw.lastupdated = $oci_update_tag
        WITH gw
        MATCH (cc:OCICompartment{id: $COMPARTMENT_ID})
        MERGE (cc)-[r:RESOURCE]->(gw)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    load_graph_data(neo4j_session, ingest, gateways, COMPARTMENT_ID=compartment_id, oci_update_tag=oci_update_tag)


def sync_gateways(
    neo4j_session: neo4j.Session,
    gateway_client: oci.apigateway.GatewayClient,
    compartment_id: str,
    region: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Fetch -> transform -> load the API gateways of one compartment in one region (the
    client is already pinned to it).
    """
    raw = get_gateway_list_data(gateway_client, compartment_id)
    gateways = transform_gateways(raw, region)
    if not gateways:
        return
    load_gateways(neo4j_session, gateways, compartment_id, oci_update_tag)
    tags.sync_tags(neo4j_session, raw, 'OCIApiGateway', oci_update_tag, common_job_parameters)
