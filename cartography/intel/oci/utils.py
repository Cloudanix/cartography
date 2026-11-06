# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI intel module - utility functions
import json
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import neo4j
from cloudconsolelink.clouds.oci import OCILinker

from cartography.client.core.tx import read_list_of_dicts_tx

logger = logging.getLogger(__name__)

oci_console_link = OCILinker()


def get_console_link(resource_name: str, **kwargs: Any) -> Optional[str]:
    """
    Build the OCI console link for a resource.

    :param resource_name: OCILinker resource name, e.g. "compute_instance", "bucket".
    :param kwargs: identifiers the link needs (region, ocid, namespace, bucket_name, ...).
    :return: the console URL, or None when a required identifier is missing.
    A missing link must never fail a sync, so OCILinker's ValueError is swallowed here.
    """
    try:
        return oci_console_link.get_console_link(resource_name=resource_name, **kwargs)
    except ValueError:
        logger.debug("No OCI console link for %s: missing identifiers", resource_name)
        return None


# Generic way to turn a OCI python object into the json response that you would see from calling the REST API.
def oci_object_to_json(in_obj: Any) -> List[Dict[str, Any]]:
    out_list = []
    for dict in json.loads(str(in_obj)):
        out_list.append(replace_char_in_dict(dict))
    return out_list


# Turn a single OCI python object (not a list) into a json dict like the REST API would return.
def oci_single_object_to_json(in_obj: Any) -> Dict[str, Any]:
    return replace_char_in_dict(json.loads(str(in_obj)))


# Have to replace _ with - in dictionary keys, since _ is substituted for - in OCI object variables.
def replace_char_in_dict(in_dict: Dict[str, Any]) -> Dict[str, Any]:
    out_dict = {}
    for dict_key, dict_val in in_dict.items():
        if isinstance(dict_val, dict):
            dict_val = replace_char_in_dict(dict_val)
        elif isinstance(dict_val, list):
            dict_val = [
                replace_char_in_dict(item) if isinstance(item, dict) else item
                for item in dict_val
            ]
        out_dict[dict_key.replace('_', '-')] = dict_val
    return out_dict


# The syncing tenancy, reached through the syncing workspace. OCITenancy is keyed by its OCID alone, so a bare
# (:OCITenancy{id}) match is also reachable from every other workspace that onboarded the same tenancy.
_WORKSPACE_TENANCY = "MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:OCITenancy{id: $OCI_TENANCY_ID})"


def _read_tenancy(
    neo4j_session: neo4j.Session, query: str, tenancy_id: str, workspace_id: str,
) -> List[Dict[str, Any]]:
    return neo4j_session.execute_read(
        read_list_of_dicts_tx, query, WORKSPACE_ID=workspace_id, OCI_TENANCY_ID=tenancy_id,
    )


# Grab list of all compartments and sub-compartments in neo4j already populated by iam.
def get_compartments_in_tenancy(
    neo4j_session: neo4j.Session, tenancy_id: str, workspace_id: str,
) -> List[Dict[str, Any]]:
    query = _WORKSPACE_TENANCY + "-[:OWNER]->(compartment:OCICompartment) " \
        "return DISTINCT compartment.name as name, compartment.ocid as ocid, " \
        "compartment.compartmentid as compartmentid;"
    return _read_tenancy(neo4j_session, query, tenancy_id, workspace_id)


# Grab list of all groups in neo4j already populated by iam. Groups and policies hang directly off the tenancy
# (iam.load_groups / load_policies); a longer or untyped path could walk through a shared node into another tenancy.
def get_groups_in_tenancy(neo4j_session: neo4j.Session, tenancy_id: str, workspace_id: str) -> List[Dict[str, Any]]:
    query = _WORKSPACE_TENANCY + "-[:RESOURCE]->(group:OCIGroup) " \
        "return DISTINCT group.name as name, group.ocid as ocid;"
    return _read_tenancy(neo4j_session, query, tenancy_id, workspace_id)


# Grab list of all policies in neo4j already populated by iam.
def get_policies_in_tenancy(neo4j_session: neo4j.Session, tenancy_id: str, workspace_id: str) -> List[Dict[str, Any]]:
    query = _WORKSPACE_TENANCY + "-[:RESOURCE]->(policy:OCIPolicy) " \
        "return DISTINCT policy.name as name, policy.ocid as ocid, policy.statements as statements, " \
        "policy.compartmentid as compartmentid;"
    return _read_tenancy(neo4j_session, query, tenancy_id, workspace_id)


# Grab list of all regions in neo4j already populated by iam.
def get_regions_in_tenancy(neo4j_session: neo4j.Session, tenancy_id: str, workspace_id: str) -> List[Dict[str, Any]]:
    query = _WORKSPACE_TENANCY + "-[:OCI_REGION_SUBSCRIPTION]->(region:OCIRegion) " \
        "return DISTINCT region.name as name, region.key as key;"
    return _read_tenancy(neo4j_session, query, tenancy_id, workspace_id)
