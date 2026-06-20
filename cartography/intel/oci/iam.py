# Copyright (c) 2020, Oracle and/or its affiliates.
# OCI Identity API-centric functions
# https://docs.cloud.oracle.com/iaas/Content/Identity/Concepts/overview.htm
import logging
import re
import time
from typing import Any
from typing import Dict
from typing import List

import neo4j
import oci

from . import utils
from cartography.client.core.tx import load_graph_data
from cartography.util import run_cleanup_job

logger = logging.getLogger(__name__)

# Standard cross-provider classification of IAM resources by who created them.
# "predefined" => created/owned by the cloud provider; "custom" => created by a customer principal.
MANAGED_TYPE_PREDEFINED = "predefined"
MANAGED_TYPE_CUSTOM = "custom"

# Groups seeded by Oracle when a tenancy is provisioned.
OCI_PREDEFINED_GROUP_NAMES = {"Administrators"}
# Policies seeded by Oracle (root tenancy admin policy and PaaS/PSM-managed policies).
OCI_PREDEFINED_POLICY_NAMES = {"Tenant Admin Policy"}
# Compartments created by Oracle rather than the customer.
OCI_PREDEFINED_COMPARTMENT_NAMES = {"ManagedCompartmentForPaaS"}


def _oci_compartment_managed_type(compartment: Dict[str, Any], tenancy_id: str) -> str:
    # The root compartment is the tenancy itself; Oracle also seeds ManagedCompartmentForPaaS.
    if compartment.get("id") == tenancy_id or compartment.get("compartmentId") == tenancy_id:
        return MANAGED_TYPE_PREDEFINED
    if compartment.get("name") in OCI_PREDEFINED_COMPARTMENT_NAMES:
        return MANAGED_TYPE_PREDEFINED
    return MANAGED_TYPE_CUSTOM


def _oci_group_managed_type(group: Dict[str, Any]) -> str:
    return MANAGED_TYPE_PREDEFINED if group.get("name") in OCI_PREDEFINED_GROUP_NAMES else MANAGED_TYPE_CUSTOM


def _oci_policy_managed_type(policy: Dict[str, Any]) -> str:
    name = policy.get("name", "") or ""
    if name in OCI_PREDEFINED_POLICY_NAMES or name.startswith("PSM-"):
        return MANAGED_TYPE_PREDEFINED
    return MANAGED_TYPE_CUSTOM


def sync_compartments(
    neo4j_session: neo4j.Session,
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    logger.debug("Syncing IAM compartments for account '%s'.", current_tenancy_id)
    data = get_compartment_list_data(iam, current_tenancy_id)
    load_compartments(neo4j_session, data['Compartments'], current_tenancy_id, oci_update_tag)
    run_cleanup_job('oci_import_compartments_cleanup.json', neo4j_session, common_job_parameters)


def get_compartment_list_data_recurse(
    iam: oci.identity.identity_client.IdentityClient,
    compartment_list: Dict[str, Any],
    compartment_id: str,
) -> None:

    response = oci.pagination.list_call_get_all_results(iam.list_compartments, compartment_id)
    if not response.data:
        return
    compartment_list.update(
        {"Compartments": list(compartment_list["Compartments"]) + utils.oci_object_to_json(response.data)},
    )
    for compartment in response.data:
        get_compartment_list_data_recurse(iam, compartment_list, compartment.id)


def get_compartment_list_data(
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
) -> Dict[str, Any]:
    compartment_list = {"Compartments": ""}
    get_compartment_list_data_recurse(iam, compartment_list, current_tenancy_id)
    return compartment_list


def load_compartments(
    neo4j_session: neo4j.Session,
    compartments: List[Dict[str, Any]],
    current_oci_tenancy_id: str,
    oci_update_tag: int,
) -> None:
    ingest_compartment = """
    UNWIND $DictList AS comp
        MERGE (cnode:OCICompartment{id: comp.ocid})
        ON CREATE SET cnode:OCICompartment, cnode.firstseen = timestamp(),
        cnode.createdate = comp.create_date
        SET cnode.ocid = comp.ocid, cnode.name = comp.name, cnode.compartmentid = comp.compartment_id,
        cnode.managed_type = comp.managed_type,
        cnode.lastupdated = $oci_update_tag
        WITH cnode
        MATCH (tenancy:OCITenancy{id: $OCI_TENANCY_ID})
        MERGE (tenancy)-[r:OWNER]->(cnode)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": compartment["id"],
            "compartment_id": compartment["compartment-id"],
            "name": compartment["name"],
            "managed_type": _oci_compartment_managed_type(
                {"id": compartment["id"], "name": compartment["name"], "compartmentId": compartment["compartment-id"]},
                current_oci_tenancy_id,
            ),
            "create_date": compartment["time-created"],
        }
        for compartment in compartments
    ]
    load_graph_data(
        neo4j_session, ingest_compartment, rows,
        OCI_TENANCY_ID=current_oci_tenancy_id, oci_update_tag=oci_update_tag,
    )


def load_users(
    neo4j_session: neo4j.Session,
    users: List[Dict[str, Any]],
    current_oci_tenancy_id: str,
    oci_update_tag: int,
) -> None:
    ingest_user = """
    UNWIND $DictList AS user
        MERGE (unode:OCIUser{id: user.ocid})
        ON CREATE SET unode:OCIUser, unode.firstseen = timestamp(),
        unode.createdate = user.create_date
        SET unode.ocid = user.ocid, unode.name = user.username, unode.compartmentid = user.compartment_id,
        unode.description = user.description,
        unode.email = user.email, unode.lifecycle_state = user.lifecycle_state,
        unode.is_mfa_activated = user.is_mfa_activated,
        unode.can_use_api_keys = user.can_use_api_keys, unode.can_use_auth_tokens = user.can_use_auth_tokens,
        unode.can_use_console_password = user.can_use_console_password,
        unode.can_use_customer_secret_keys = user.can_use_customer_secret_keys,
        unode.can_use_smtp_credentials = user.can_use_smtp_credentials,
        unode.managed_type = user.managed_type,
        unode.lastupdated = $oci_update_tag
        WITH unode
        MATCH (aa:OCITenancy{id: $OCI_TENANCY_ID})
        MERGE (aa)-[r:RESOURCE]->(unode)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": user["id"],
            "create_date": str(user["time-created"]),
            "username": user["name"],
            "description": user["description"],
            "email": user["email"],
            "lifecycle_state": user["lifecycle-state"],
            "is_mfa_activated": user["is-mfa-activated"],
            "can_use_api_keys": user["capabilities"]["can-use-api-keys"],
            "can_use_auth_tokens": user["capabilities"]["can-use-auth-tokens"],
            "can_use_console_password": user["capabilities"]["can-use-console-password"],
            "can_use_customer_secret_keys": user["capabilities"]["can-use-customer-secret-keys"],
            "can_use_smtp_credentials": user["capabilities"]["can-use-smtp-credentials"],
            "compartment_id": user["compartment-id"],
            "managed_type": MANAGED_TYPE_CUSTOM,
        }
        for user in users
    ]
    load_graph_data(
        neo4j_session, ingest_user, rows,
        OCI_TENANCY_ID=current_oci_tenancy_id, oci_update_tag=oci_update_tag,
    )


def get_user_list_data(
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    response = oci.pagination.list_call_get_all_results(iam.list_users, current_tenancy_id)
    return {'Users': utils.oci_object_to_json(response.data)}


def sync_users(
    neo4j_session: neo4j.Session,
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    tic = time.perf_counter()
    logger.debug("Syncing IAM users for account '%s'.", current_tenancy_id)
    data = get_user_list_data(iam, current_tenancy_id)
    load_users(neo4j_session, data['Users'], current_tenancy_id, oci_update_tag)
    run_cleanup_job('oci_import_users_cleanup.json', neo4j_session, common_job_parameters)
    logger.info(f"Time to process OCI IAM users for tenancy '{current_tenancy_id}' ({len(data['Users'])} users): {time.perf_counter() - tic:0.4f} seconds")


def get_group_list_data(
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    response = oci.pagination.list_call_get_all_results(iam.list_groups, current_tenancy_id)
    return {'Groups': utils.oci_object_to_json(response.data)}


def load_groups(
    neo4j_session: neo4j.Session,
    groups: List[Dict[str, Any]],
    current_tenancy_id: str,
    oci_update_tag: int,
) -> None:
    ingest_group = """
    UNWIND $DictList AS grp
        MERGE (gnode:OCIGroup{id: grp.ocid})
        ON CREATE SET gnode.firstseen = timestamp(), gnode.createdate = grp.create_date
        SET gnode.ocid = grp.ocid, gnode.name = grp.group_name, gnode.compartmentid = grp.compartment_id,
        gnode.lastupdated = $oci_update_tag,
        gnode.managed_type = grp.managed_type,
        gnode.description = grp.description
        WITH gnode
        MATCH (aa:OCITenancy{id: $OCI_TENANCY_ID})
        MERGE (aa)-[r:RESOURCE]->(gnode)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": group["id"],
            "create_date": str(group["time-created"]),
            "group_name": group["name"],
            "compartment_id": group["compartment-id"],
            "description": group["description"],
            "managed_type": _oci_group_managed_type(group),
        }
        for group in groups
    ]
    load_graph_data(
        neo4j_session, ingest_group, rows,
        OCI_TENANCY_ID=current_tenancy_id, oci_update_tag=oci_update_tag,
    )


def sync_groups(
    neo4j_session: neo4j.Session,
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    tic = time.perf_counter()
    logger.debug("Syncing IAM groups for account '%s'.", current_tenancy_id)
    data = get_group_list_data(iam, current_tenancy_id)
    load_groups(neo4j_session, data["Groups"], current_tenancy_id, oci_update_tag)
    run_cleanup_job('oci_import_groups_cleanup.json', neo4j_session, common_job_parameters)
    logger.info(f"Time to process OCI IAM groups for tenancy '{current_tenancy_id}' ({len(data['Groups'])} groups): {time.perf_counter() - tic:0.4f} seconds")


def get_group_membership_data(
    iam: oci.identity.identity_client.IdentityClient,
    group_id: str,
    current_tenancy_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    response = oci.pagination.list_call_get_all_results(
        iam.list_user_group_memberships, compartment_id=current_tenancy_id, group_id=group_id,
    )
    return {'GroupMemberships': utils.oci_object_to_json(response.data)}


def sync_group_memberships(
    neo4j_session: neo4j.Session,
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    logger.debug("Syncing IAM group membership for account '%s'.", current_tenancy_id)
    query = "MATCH (group:OCIGroup)<-[:RESOURCE]-(OCITenancy{id: $OCI_TENANCY_ID}) " \
            "return group.name as name, group.ocid as ocid;"
    groups = neo4j_session.run(query, OCI_TENANCY_ID=current_tenancy_id)
    groups_membership = {
        group["ocid"]: get_group_membership_data(iam, group['ocid'], current_tenancy_id) for group in groups
    }
    load_group_memberships(neo4j_session, groups_membership, oci_update_tag)
    run_cleanup_job(
        'oci_import_groups_membership_cleanup.json',
        neo4j_session,
        common_job_parameters,
    )


def load_group_memberships(
    neo4j_session: neo4j.Session,
    group_memberships: Dict[str, Any],
    oci_update_tag: int,
) -> None:
    ingest_membership = """
    UNWIND $DictList AS m
        MATCH (group:OCIGroup{id: m.group_ocid})
        WITH group, m
        MATCH (user:OCIUser{id: m.user_ocid})
        MERGE (user)-[r:MEMBER_OCID_GROUP]->(group)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    rows = []
    for group_ocid, membership_data in group_memberships.items():
        for info in membership_data["GroupMemberships"]:
            rows.append({
                "group_ocid": info["group-id"],
                "user_ocid": info["user-id"],
            })
    load_graph_data(
        neo4j_session, ingest_membership, rows,
        oci_update_tag=oci_update_tag,
    )


def load_policies(
    neo4j_session: neo4j.Session,
    policies: List[Dict[str, Any]],
    current_tenancy_id: str,
    oci_update_tag: int,
) -> None:
    ingest_policy = """
    UNWIND $DictList AS policy
        MERGE (pnode:OCIPolicy{id: policy.ocid})
        ON CREATE SET pnode.firstseen = timestamp(), pnode.createdate = policy.create_date
        SET pnode.ocid = policy.ocid, pnode.name = policy.policy_name, pnode.compartmentid = policy.compartment_id,
        pnode.description = policy.description,
        pnode.statements = policy.statements,
        pnode.managed_type = policy.managed_type,
        pnode.updatedate = policy.policy_update, pnode.lastupdated = $oci_update_tag
        With pnode
        MATCH (aa:OCITenancy{id: $OCI_TENANCY_ID})
        MERGE (aa)-[r:RESOURCE]->(pnode)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """

    rows = [
        {
            "ocid": policy["id"],
            "policy_name": policy["name"],
            "compartment_id": policy["compartment-id"],
            "description": policy["description"],
            "statements": policy["statements"],
            "managed_type": _oci_policy_managed_type(policy),
            "create_date": str(policy["time-created"]),
            "policy_update": str(policy["version-date"]),
        }
        for policy in policies
    ]
    load_graph_data(
        neo4j_session, ingest_policy, rows,
        OCI_TENANCY_ID=current_tenancy_id, oci_update_tag=oci_update_tag,
    )


def get_policy_list_data(
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    response = oci.pagination.list_call_get_all_results(iam.list_policies, compartment_id=current_tenancy_id)
    return {'Policies': utils.oci_object_to_json(response.data)}


def sync_policies(
    neo4j_session: neo4j.Session,
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    logger.debug("Syncing IAM policies for account '%s'.", current_tenancy_id)
    compartments = utils.get_compartments_in_tenancy(neo4j_session, current_tenancy_id)
    for compartment in compartments:
        logger.debug(
            "Syncing OCI policies for compartment '%s' in account '%s'.", compartment['ocid'], current_tenancy_id,
        )
        data = get_policy_list_data(iam, compartment["ocid"])
        if (data["Policies"]):
            load_policies(neo4j_session, data["Policies"], current_tenancy_id, oci_update_tag)
    run_cleanup_job('oci_import_policies_cleanup.json', neo4j_session, common_job_parameters)


def load_oci_policy_group_reference(
    neo4j_session: neo4j.Session,
    policy_id: str,
    group_id: str,
    tenancy_id: str,
    oci_update_tag: int,
) -> None:
    ingest_policy_group_reference = """
    MATCH (aa:OCIPolicy{id: $POLICY_ID})
    MATCH (bb:OCIGroup{id: $GROUP_ID})
    MERGE (aa)-[r:OCI_POLICY_REFERENCE]->(bb)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $oci_update_tag
    """
    neo4j_session.run(
        ingest_policy_group_reference,
        POLICY_ID=policy_id,
        GROUP_ID=group_id,
        oci_update_tag=oci_update_tag,
    )


def load_oci_policy_compartment_reference(
    neo4j_session: neo4j.Session,
    policy_id: str,
    compartment_id: str,
    tenancy_id: str,
    oci_update_tag: int,
) -> None:
    ingest_policy_compartment_reference = """
    MATCH (aa:OCIPolicy{id: $POLICY_ID})
    MATCH (bb:OCICompartment{id: $COMPARTMENT_ID})
    MERGE (aa)-[r:OCI_POLICY_REFERENCE]->(bb)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $oci_update_tag
    """
    neo4j_session.run(
        ingest_policy_compartment_reference,
        POLICY_ID=policy_id,
        COMPARTMENT_ID=compartment_id,
        oci_update_tag=oci_update_tag,
    )


# Parse the statements inside OCI Policies and load the corresponding relationships they reference.
def sync_oci_policy_references(
    neo4j_session: neo4j.Session,
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    groups = list(utils.get_groups_in_tenancy(neo4j_session, tenancy_id))
    compartments = list(utils.get_compartments_in_tenancy(neo4j_session, tenancy_id))
    policies = list(utils.get_policies_in_tenancy(neo4j_session, tenancy_id))
    for policy in policies:
        check_compart = policy["compartmentid"]
        for statement in policy["statements"]:
            m = re.search('(?<=group\\s)[^ ]*(?=\\s)', statement)
            if m:
                for group in groups:
                    if group["name"].lower() == m.group(0).lower():
                        load_oci_policy_group_reference(
                            neo4j_session, policy["ocid"], group["ocid"], tenancy_id, oci_update_tag,
                        )
            m = re.search('(?<=compartment\\s)[^ ]*(?=$)', statement)
            if m:
                for compartment in compartments:
                    # Only look at the compartment or subcompartment name referenced in the policy statement
                    # in which the policy is a member of.
                    if compartment["ocid"] == check_compart or compartment["compartmentid"] == check_compart:
                        if compartment["name"].lower() == m.group(0).lower():
                            load_oci_policy_compartment_reference(
                                neo4j_session, policy["ocid"], compartment['ocid'], tenancy_id, oci_update_tag,
                            )


def get_region_subscriptions_list_data(
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
) -> Dict[str, List[Dict[str, Any]]]:
    response = oci.pagination.list_call_get_all_results(iam.list_region_subscriptions, current_tenancy_id)
    return {'RegionSubscriptions': utils.oci_object_to_json(response.data)}


def load_region_subscriptions(
    neo4j_session: neo4j.Session,
    regions: List[Dict[str, Any]],
    tenancy_id: str,
    oci_update_tag: int,
) -> None:
    query = """
    UNWIND $DictList AS region
        MERGE (aa:OCIRegion{id: region.region_key})
        ON CREATE SET aa.firstseen = timestamp()
        SET aa.key = region.region_key, aa.ocid = region.region_key, aa.lastupdated = $oci_update_tag,
        aa.name = region.region_name,
        aa.managed_type = $MANAGED_TYPE
        WITH aa
        MATCH (bb:OCITenancy{id: $OCI_TENANCY_ID})
        MERGE (bb)-[r:OCI_REGION_SUBSCRIPTION]->(aa)
        ON CREATE SET r.firstseen = timestamp()
        SET r.lastupdated = $oci_update_tag
    """
    rows = [
        {
            "region_key": region["region-key"],
            "region_name": region["region-name"],
        }
        for region in regions
    ]
    load_graph_data(
        neo4j_session, query, rows,
        MANAGED_TYPE=MANAGED_TYPE_PREDEFINED,
        oci_update_tag=oci_update_tag,
        OCI_TENANCY_ID=tenancy_id,
    )


def sync_region_subscriptions(
    neo4j_session: neo4j.Session,
    iam: oci.identity.identity_client.IdentityClient,
    current_tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
) -> None:
    logger.debug("Syncing IAM region subscriptions for account '%s'.", current_tenancy_id)
    data = get_region_subscriptions_list_data(iam, current_tenancy_id)
    load_region_subscriptions(neo4j_session, data["RegionSubscriptions"], current_tenancy_id, oci_update_tag)
    # run_cleanup_job('oci_import_region_subscriptions_cleanup.json', neo4j_session, common_job_parameters)


def sync(
    neo4j_session: neo4j.Session,
    iam: oci.identity.identity_client.IdentityClient,
    tenancy_id: str,
    oci_update_tag: int,
    common_job_parameters: Dict[str, Any],
    regions: List[str] = None,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing IAM for account '%s'.", tenancy_id)
    sync_users(neo4j_session, iam, tenancy_id, oci_update_tag, common_job_parameters)
    sync_groups(neo4j_session, iam, tenancy_id, oci_update_tag, common_job_parameters)
    sync_group_memberships(neo4j_session, iam, tenancy_id, oci_update_tag, common_job_parameters)
    # Compartment sync is handled by compartment.py in __init__.py, not here
    # sync_compartments(neo4j_session, iam, tenancy_id, oci_update_tag, common_job_parameters)
    sync_policies(neo4j_session, iam, tenancy_id, oci_update_tag, common_job_parameters)
    sync_oci_policy_references(neo4j_session, tenancy_id, oci_update_tag, common_job_parameters)
    sync_region_subscriptions(neo4j_session, iam, tenancy_id, oci_update_tag, common_job_parameters)
    toc = time.perf_counter()
    logger.info(f"Time to process OCI IAM for tenancy '{tenancy_id}': {toc - tic:0.4f} seconds")
