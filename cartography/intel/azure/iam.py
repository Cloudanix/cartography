import logging
from typing import Dict
from typing import List

import neo4j
from azure.core.exceptions import HttpResponseError
from azure.graphrbac import GraphRbacManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient

from .util.credentials import Credentials
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


def load_tenant_users(session: neo4j.Session, tenant_id: str, data_list: List[Dict], update_tag: int) -> None:
    session.write_transaction(_load_tenant_users_tx, tenant_id, data_list, update_tag)


def load_roles(session: neo4j.Session, data_list: List[Dict], update_tag: int) -> None:
    session.write_transaction(_load_roles_tx, data_list, update_tag)


def load_tenant_groups(session: neo4j.Session, tenant_id: str, data_list: List[Dict], update_tag: int) -> None:
    session.write_transaction(_load_tenant_groups_tx, tenant_id, data_list, update_tag)


def load_tenant_applications(session: neo4j.Session, tenant_id: str, data_list: List[Dict], update_tag: int) -> None:
    session.write_transaction(_load_tenant_applications_tx, tenant_id, data_list, update_tag)


def load_tenant_service_accounts(
    session: neo4j.Session, tenant_id: str, data_list: List[Dict], update_tag: int,
) -> None:
    session.write_transaction(_load_tenant_service_accounts_tx, tenant_id, data_list, update_tag)


def load_tenant_domains(session: neo4j.Session, tenant_id: str, data_list: List[Dict], update_tag: int) -> None:
    session.write_transaction(_load_tenant_domains_tx, tenant_id, data_list, update_tag)


@timeit
def get_graph_client(credentials: Credentials, tenant_id: str) -> GraphRbacManagementClient:
    client = GraphRbacManagementClient(credentials, tenant_id)
    return client


@timeit
def get_authorization_client(credentials: Credentials, subscription_id: str) -> AuthorizationManagementClient:
    client = AuthorizationManagementClient(credentials, subscription_id)
    return client


@timeit
def get_tenant_users_list(client: GraphRbacManagementClient) -> List[Dict]:
    try:
        tenant_users_list = list(
            map(lambda x: x.as_dict(), client.users.list()),
        )

        return tenant_users_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant users - {e}")
        return []


def _load_tenant_users_tx(
    tx: neo4j.Transaction, tenant_id: str, tenant_users_list: List[Dict], update_tag: int,
) -> None:
    ingest_user = """
    UNWIND {tenant_users_list} AS user
    MERGE (i:AzureUser{id: user.object_id})
    ON CREATE SET i.firstseen = timestamp(),
    i.name = user.display_name,
    i.given_name = user.given_name,
    i.surname = user.surname,
    i.user_type = user.user_type,
    i.mobile = user.mobile
    SET i.lastupdated = {update_tag},
    i.account_enabled = user.account_enabled,
    i.refreshTokensValidFromDateTime = user.refreshTokensValidFromDateTime,
    i.user_principal_name = user.user_principal_name
    WITH i
    MATCH (owner:AzureTenant{id: {tenant_id}})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    tx.run(
        ingest_user,
        tenant_users_list=tenant_users_list,
        tenant_id=tenant_id,
        update_tag=update_tag,
    )


def cleanup_tenant_users(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_users_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_users(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_graph_client(credentials, tenant_id)
    tenant_users_list = get_tenant_users_list(client)
    load_tenant_users(neo4j_session, tenant_id, tenant_users_list, update_tag)
    cleanup_tenant_users(neo4j_session, common_job_parameters)


@timeit
def get_tenant_groups_list(client: GraphRbacManagementClient) -> List[Dict]:
    try:
        tenant_groups_list = list(map(lambda x: x.as_dict(), client.groups.list()))

        return tenant_groups_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant groups - {e}")
        return []


def _load_tenant_groups_tx(
    tx: neo4j.Transaction, tenant_id: str, tenant_groups_list: List[Dict], update_tag: int,
) -> None:
    ingest_group = """
    UNWIND {tenant_groups_list} AS group
    MERGE (i:AzureGroup{id: group.object_id})
    ON CREATE SET i.firstseen = timestamp(),
    i.visibility = group.visibility,
    i.classification = group.classification,
    i.createdDateTime = group.createdDateTime,
    i.securityEnabled = group.security_enabled
    SET i.lastupdated = {update_tag},
    i.mail = group.mail
    WITH i
    MATCH (owner:AzureTenant{id: {tenant_id}})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    tx.run(
        ingest_group,
        tenant_groups_list=tenant_groups_list,
        tenant_id=tenant_id,
        update_tag=update_tag,
    )


def cleanup_tenant_groups(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_groups_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_groups(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_graph_client(credentials, tenant_id)
    tenant_groups_list = get_tenant_groups_list(client)
    load_tenant_groups(neo4j_session, tenant_id, tenant_groups_list, update_tag)
    cleanup_tenant_groups(neo4j_session, common_job_parameters)


@timeit
def get_tenant_applications_list(client: GraphRbacManagementClient) -> List[Dict]:
    try:
        tenant_applications_list = list(map(lambda x: x.as_dict(), client.applications.list()))

        return tenant_applications_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant applications - {e}")
        return []


def _load_tenant_applications_tx(
    tx: neo4j.Transaction, tenant_id: str, tenant_applications_list: List[Dict], update_tag: int,
) -> None:
    ingest_app = """
    UNWIND {tenant_applications_list} AS app
    MERGE (i:AzureApplication{id: app.object_id})
    ON CREATE SET i.firstseen = timestamp(),
    i.displayName = app.display_name,
    i.publisherDomain = app.publisher_domain
    SET i.lastupdated = {update_tag},
    i.signInAudience = app.sign_in_audience
    WITH i
    MATCH (owner:AzureTenant{id: {tenant_id}})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    tx.run(
        ingest_app,
        tenant_applications_list=tenant_applications_list,
        tenant_id=tenant_id,
        update_tag=update_tag,
    )


def cleanup_tenant_applications(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_applications_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_applications(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_graph_client(credentials, tenant_id)
    tenant_applications_list = get_tenant_applications_list(client)
    load_tenant_applications(neo4j_session, tenant_id, tenant_applications_list, update_tag)
    cleanup_tenant_applications(neo4j_session, common_job_parameters)


@timeit
def get_tenant_service_accounts_list(client: GraphRbacManagementClient) -> List[Dict]:
    try:
        tenant_service_accounts_list = list(
            map(lambda x: x.as_dict(), client.service_principals.list()),
        )

        return tenant_service_accounts_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant service accounts - {e}")
        return []


def _load_tenant_service_accounts_tx(
    tx: neo4j.Transaction, tenant_id: str, tenant_service_accounts_list: List[Dict], update_tag: int,
) -> None:
    ingest_app = """
    UNWIND {tenant_service_accounts_list} AS service
    MERGE (i:AzureServiceAccount{id: service.object_id})
    ON CREATE SET i.firstseen = timestamp(),
    i.name = service.display_name,
    i.accountEnabled = service.account_enabled,
    i.servicePrincipalType = service.service_principal_type
    SET i.lastupdated = {update_tag},
    i.signInAudience = service.signInAudience
    WITH i
    MATCH (owner:AzureTenant{id: {tenant_id}})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    tx.run(
        ingest_app,
        tenant_service_accounts_list=tenant_service_accounts_list,
        tenant_id=tenant_id,
        update_tag=update_tag,
    )


def cleanup_tenant_service_accounts(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_service_accounts_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_service_accounts(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_graph_client(credentials, tenant_id)
    tenant_service_accounts_list = get_tenant_service_accounts_list(client)
    load_tenant_service_accounts(neo4j_session, tenant_id, tenant_service_accounts_list, update_tag)
    cleanup_tenant_service_accounts(neo4j_session, common_job_parameters)


@timeit
def get_tenant_domains_list(client: GraphRbacManagementClient) -> List[Dict]:
    try:
        tenant_domains_list = list(map(lambda x: x.as_dict(), client.domains.list()))

        return tenant_domains_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant domains - {e}")
        return []


def _load_tenant_domains_tx(
    tx: neo4j.Transaction, tenant_id: str, tenant_domains_list: List[Dict], update_tag: int,
) -> None:
    ingest_domain = """
    UNWIND {tenant_domains_list} AS domain
    MERGE (i:AzureDomain{name: domain.name})
    ON CREATE SET i.firstseen = timestamp(),
    i.isRoot = domain.isRoot,
    i.isInitial = domain.isInitial
    SET i.lastupdated = {update_tag},
    i.authenticationType = domain.authentication_type,
    i.availabilityStatus = domain.availabilityStatus
    WITH i
    MATCH (owner:AzureTenant{id: {tenant_id}})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    tx.run(
        ingest_domain,
        tenant_domains_list=tenant_domains_list,
        tenant_id=tenant_id,
        update_tag=update_tag,
    )


def cleanup_tenant_domains(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_domains_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_domains(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_graph_client(credentials, tenant_id)
    tenant_domains_list = get_tenant_domains_list(client)
    load_tenant_domains(neo4j_session, tenant_id, tenant_domains_list, update_tag)
    cleanup_tenant_domains(neo4j_session, common_job_parameters)


@timeit
def get_roles_list(client: AuthorizationManagementClient) -> List[Dict]:
    try:
        roles_list = list(
            map(lambda x: x.as_dict(), client.role_assignments.list()),
        )

        for role in roles_list:
            result = client.role_definitions.get_by_id(role["role_definition_id"], raw=True)
            result = result.response.json()
            role['roleName'] = result['properties']['roleName']
            role['permissions'] = result['properties']['permissions']

        return roles_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving roles - {e}")
        return []


def _load_roles_tx(
    tx: neo4j.Transaction, roles_list: List[Dict], update_tag: int,
) -> None:
    ingest_role = """
    UNWIND {roles_list} AS role
    MERGE (i:AzureRole{id: role.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.name = role.name,
    i.type = role.type
    SET i.lastupdated = {update_tag},
    i.roleName = role.roleName,
    i.permissions = role.permissions
    WITH i,role
    MATCH (owner) where owner.id = role.principal_id
    MERGE (owner)-[r:ASSUME_ROLE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    tx.run(
        ingest_role,
        roles_list=roles_list,
        update_tag=update_tag,
    )


def cleanup_roles(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_roles_cleanup.json', neo4j_session, common_job_parameters)


def sync_roles(
    neo4j_session: neo4j.Session, credentials: Credentials, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_authorization_client(credentials.arm_credentials, credentials.subscription_id)
    roles_list = get_roles_list(client)
    load_roles(neo4j_session, roles_list, update_tag)
    cleanup_roles(neo4j_session, common_job_parameters)


@ timeit
def sync(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    logger.info("Syncing IAM for Tenant '%s'.", tenant_id)

    sync_tenant_users(neo4j_session, credentials.aad_graph_credentials, tenant_id, update_tag, common_job_parameters)
    sync_tenant_groups(neo4j_session, credentials.aad_graph_credentials, tenant_id, update_tag, common_job_parameters)
    sync_tenant_applications(
        neo4j_session, credentials.aad_graph_credentials,
        tenant_id, update_tag, common_job_parameters,
    )
    sync_tenant_service_accounts(
        neo4j_session, credentials.aad_graph_credentials,
        tenant_id, update_tag, common_job_parameters,
    )
    sync_tenant_domains(neo4j_session, credentials.aad_graph_credentials, tenant_id, update_tag, common_job_parameters)
    sync_roles(
        neo4j_session, credentials.arm_credentials, update_tag, common_job_parameters,
    )
