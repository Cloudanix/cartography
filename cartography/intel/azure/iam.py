import asyncio
import logging
import math
from datetime import datetime
from typing import Dict
from typing import List

import neo4j
from azure.core.exceptions import HttpResponseError
from azure.graphrbac import GraphRbacManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient
from cloudconsolelink.clouds.azure import AzureLinker
from msgraph import GraphServiceClient

from .util.credentials import Credentials
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
azure_console_link = AzureLinker()

scopes = ['https://graph.microsoft.com/.default']


def load_tenant_users(session: neo4j.Session, tenant_id: str, data_list: List[Dict], update_tag: int) -> None:
    iteration_size = 500
    total_items = len(data_list)
    total_iterations = math.ceil(len(data_list) / iteration_size)

    for counter in range(0, total_iterations):
        start = iteration_size * (counter)

        if (start + iteration_size) >= total_items:
            end = total_items
            paged_users = data_list[start:]

        else:
            end = start + iteration_size
            paged_users = data_list[start:end]

        session.write_transaction(_load_tenant_users_tx, tenant_id, paged_users, update_tag)

        logger.info(f"Iteration {counter + 1} of {total_iterations}. {start} - {end} - {len(paged_users)}")


def load_roles(session: neo4j.Session, tenant_id: str, data_list: List[Dict], role_assignments_list: List[Dict], update_tag: int, SUBSCRIPTION_ID: str) -> None:
    session.write_transaction(_load_roles_tx, tenant_id, data_list, role_assignments_list, update_tag, SUBSCRIPTION_ID)


def load_managed_identities(session: neo4j.Session, tenant_id: str, data_list: List[Dict], update_tag: int) -> None:
    session.write_transaction(_load_managed_identities_tx, tenant_id, data_list, update_tag)


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


def set_used_state(session: neo4j.Session, tenant_id: str, common_job_parameters: Dict, update_tag: int) -> None:
    session.write_transaction(_set_used_state_tx, tenant_id, common_job_parameters, update_tag)


@timeit
def get_graph_client(credentials: Credentials, tenant_id: str) -> GraphRbacManagementClient:
    client = GraphRbacManagementClient(credentials, tenant_id)
    return client


@timeit
def get_default_graph_client(credentials: Credentials) -> GraphServiceClient:
    client = GraphServiceClient(credentials, scopes)
    return client


@timeit
def get_authorization_client(credentials: Credentials, subscription_id: str) -> AuthorizationManagementClient:
    client = AuthorizationManagementClient(credentials, subscription_id)
    return client


@timeit
def get_managed_identity_client(credentials: Credentials, subscription_id: str) -> ManagedServiceIdentityClient:
    client = ManagedServiceIdentityClient(credentials, subscription_id)
    return client


@timeit
def list_tenant_users(client: GraphServiceClient, tenant_id: str) -> List[Dict]:
    """
    List users using Microsoft Graph API
    Docs: https://learn.microsoft.com/en-us/graph/api/user-list
    """
    try:
        users_response = client.users.get()

        users = transform_users(users_response.value, tenant_id)
        return users

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant users - {e}")
        return []


def transform_users(users_list: List[Dict], tenant_id: str) -> List[Dict]:
    """
    Transform user objects from MS Graph API format
    Docs: https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0
    """
    users: List[Dict] = []

    for user in users_list:
        # Only include properties from default response
        usr = {
            'id': f"tenants/{tenant_id}/users/{user.id}",
            'consolelink': azure_console_link.get_console_link(id=user.id, iam_entity_type='user'),
            'objectType': '#microsoft.graph.user',
            'object_id': user.id,
            'userPrincipalName': user.userPrincipalName,
            'businessPhones': user.businessPhones or [],
            'displayName': user.displayName,
            'givenName': user.givenName,
            'surname': user.surname,
            'jobTitle': user.jobTitle,
            'mail': user.mail,
            'mobilePhone': user.mobilePhone,
            'officeLocation': user.officeLocation,
            'preferredLanguage': user.preferredLanguage,
        }
        users.append(usr)

    return users


def transform_user(user: Dict, tenant_id: str) -> Dict:
    # User properties - https://learn.microsoft.com/en-us/graph/api/resources/user?view=graph-rest-1.0
    return {
        'id': f"tenants/{tenant_id}/users/{user.id}",
        'consolelink': azure_console_link.get_console_link(id=user.object_id, iam_entity_type='user'),
        'object_id': user.object_id,
        'user_principal_name': user.user_principal_name,
        'email': user.mail,
        'name': user.display_name,
        'given_name': user.given_name,
        'surname': user.surname,
        'user_type': user.user_type,
        'object_type': user.object_type,
        'mail_nickname': user.mail_nickname,
        'account_enabled': user.account_enabled,
        'usage_location': user.usage_location,
        'deletion_timestamp': user.deletion_timestamp,
        'create_date': user.additional_properties['createdDateTime'],
        'company_name': user.additional_properties['companyName'],
        'refresh_tokens_valid_from': user.additional_properties['refreshTokensValidFromDateTime'],
        'mobile': user.additional_properties['mobile'],
    }


def _load_tenant_users_tx(
    tx: neo4j.Transaction,
    tenant_id: str,
    tenant_users_list: List[Dict],
    update_tag: int,
) -> None:
    """Load Azure users into Neo4j"""
    ingest_user = """
    UNWIND $tenant_users_list AS user
    MERGE (i:AzureUser{id: user.id})
    ON CREATE SET i:AzurePrincipal,
    i.firstseen = timestamp()
    SET i.lastupdated = $update_tag,
        i.object_id = user.object_id,
        i.consolelink = user.consolelink,
        i.object_type = user.objectType,
        i.user_principal_name = user.userPrincipalName,
        i.business_phones = user.businessPhones,
        i.display_name = user.displayName,
        i.given_name = user.givenName,
        i.surname = user.surname,
        i.job_title = user.jobTitle,
        i.mail = user.mail,
        i.mobile_phone = user.mobilePhone,
        i.office_location = user.officeLocation,
        i.preferred_language = user.preferredLanguage,
        i.region = $region
    WITH i
    MATCH (owner:AzureTenant{id: $tenant_id})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    tx.run(
        ingest_user,
        region="global",
        tenant_users_list=tenant_users_list,
        createDate=datetime.utcnow(),
        tenant_id=tenant_id,
        update_tag=update_tag,
    )


def cleanup_tenant_users(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_users_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_users(
    neo4j_session: neo4j.Session,
    credentials: Credentials,
    tenant_id: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    """Sync users from Microsoft Graph API to neo4j"""
    client = get_default_graph_client(credentials.default_graph_credentials)
    tenant_users_list = list_tenant_users(client, tenant_id)

    load_tenant_users(neo4j_session, tenant_id, tenant_users_list, update_tag)
    cleanup_tenant_users(neo4j_session, common_job_parameters)


@timeit
def get_tenant_groups_list(client: GraphServiceClient, tenant_id: str) -> List[Dict]:
    """
    List groups using Microsoft Graph API
    Docs: https://learn.microsoft.com/en-us/graph/api/group-list
    """
    try:
        groups_response = client.groups.get()
        
        if not groups_response or not groups_response.value:
            return []

        tenant_groups_list = []
        for group in groups_response.value:
            group.id = f"tenants/{tenant_id}/Groups/{group.id}"
            group.consolelink = azure_console_link.get_console_link(
                iam_entity_type='group',
                id=group.id
            )
            tenant_groups_list.append(group)

        return tenant_groups_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant groups - {e}")
        return []


def _load_tenant_groups_tx(
    tx: neo4j.Transaction,
    tenant_id: str,
    tenant_groups_list: List[Dict],
    update_tag: int,
) -> None:
    """Load Azure groups into Neo4j"""
    ingest_group = """
    UNWIND $tenant_groups_list AS group
    MERGE (i:AzureGroup{id: group.id})
    ON CREATE SET i:AzurePrincipal,
    i.firstseen = timestamp()
    SET i.lastupdated = $update_tag,
        i.object_id = group.id,
        i.deleted_date_time = group.deletedDateTime,
        i.classification = group.classification,
        i.created_date_time = group.createdDateTime,
        i.creation_options = group.creationOptions,
        i.description = group.description,
        i.display_name = group.displayName,
        i.expiration_date_time = group.expirationDateTime,
        i.group_types = group.groupTypes,
        i.is_assignable_to_role = group.isAssignableToRole,
        i.mail = group.mail,
        i.mail_enabled = group.mailEnabled,
        i.mail_nickname = group.mailNickname,
        i.membership_rule = group.membershipRule,
        i.membership_rule_processing_state = group.membershipRuleProcessingState,
        i.on_premises_domain_name = group.onPremisesDomainName,
        i.on_premises_last_sync_date_time = group.onPremisesLastSyncDateTime,
        i.on_premises_net_bios_name = group.onPremisesNetBiosName,
        i.on_premises_sam_account_name = group.onPremisesSamAccountName,
        i.on_premises_security_identifier = group.onPremisesSecurityIdentifier,
        i.on_premises_sync_enabled = group.onPremisesSyncEnabled,
        i.preferred_data_location = group.preferredDataLocation,
        i.preferred_language = group.preferredLanguage,
        i.proxy_addresses = group.proxyAddresses,
        i.renewed_date_time = group.renewedDateTime,
        i.resource_behavior_options = group.resourceBehaviorOptions,
        i.resource_provisioning_options = group.resourceProvisioningOptions,
        i.security_enabled = group.securityEnabled,
        i.security_identifier = group.securityIdentifier,
        i.theme = group.theme,
        i.unique_name = group.uniqueName,
        i.visibility = group.visibility,
        i.on_premises_provisioning_errors = group.onPremisesProvisioningErrors,
        i.service_provisioning_errors = group.serviceProvisioningErrors,
        i.consolelink = group.consolelink,
        i.region = $region
    WITH i
    MATCH (owner:AzureTenant{id: $tenant_id})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    tx.run(
        ingest_group,
        region="global",
        tenant_groups_list=tenant_groups_list,
        tenant_id=tenant_id,
        createDate=datetime.utcnow(),
        update_tag=update_tag,
    )


async def get_group_members(credentials: Credentials, group_id: str):
    client: GraphServiceClient = get_default_graph_client(credentials.default_graph_credentials)
    members_data = []
    try:
        members = await client.groups.by_group_id(group_id.split("/")[-1]).members.get()

        if members and members.value:
            for member in members.value:
                members_data.append({
                    "id": member.id,
                    "display_name": member.display_name,
                    "mail": member.mail,
                    "group_id": group_id,
                })
    except Exception as e:
        logger.warning(f"error to get members of group {group_id} - {e}")
    return members_data


@timeit
def load_group_memberships(neo4j_session: neo4j.Session, memberships: List[Dict], update_tag: int) -> None:
    neo4j_session.write_transaction(_load_group_memberships_tx, memberships, update_tag)


@timeit
def _load_group_memberships_tx(tx: neo4j.Transaction, memberships: List[Dict], update_tag: int) -> None:
    ingest_memberships = """
    UNWIND $memberships AS membership
        MATCH (p:AzureGroup{id: membership.group_id})
        MATCH (pr:AzurePrincipal{object_id: membership.id})
        WITH p,pr
        MERGE (pr)-[r:MEMBER_AZURE_GROUP]->(p)
        ON CREATE SET
                r.firstseen = timestamp()
        SET
                r.lastupdated = $update_tag
    """

    tx.run(
        ingest_memberships,
        memberships=memberships,
        update_tag=update_tag,
    )


def cleanup_tenant_groups(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_groups_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_groups(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_default_graph_client(credentials.default_graph_credentials)
    tenant_groups_list = get_tenant_groups_list(client, tenant_id)

    load_tenant_groups(neo4j_session, tenant_id, tenant_groups_list, update_tag)
    for group in tenant_groups_list:
        memberships = asyncio.run(get_group_members(credentials, group["id"]))
        load_group_memberships(neo4j_session, memberships, update_tag)

    cleanup_tenant_groups(neo4j_session, common_job_parameters)


@timeit
def get_tenant_applications_list(client: GraphServiceClient, tenant_id: str) -> List[Dict]:
    """
    List applications using Microsoft Graph API
    Docs: https://learn.microsoft.com/en-us/graph/api/application-list
    """
    try:
        apps_response = client.applications.get()

        if not apps_response or not apps_response.value:
            return []

        tenant_applications_list = []
        for app in apps_response.value:
            # Only modify custom properties
            app.id = f"tenants/{tenant_id}/Applications/{app.id}"
            app.consolelink = azure_console_link.get_console_link(
                iam_entity_type='application',
                id=app.appId,
            )
            tenant_applications_list.append(app)

        return tenant_applications_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant applications - {e}")
        return []


def _load_tenant_applications_tx(
    tx: neo4j.Transaction,
    tenant_id: str,
    tenant_applications_list: List[Dict],
    update_tag: int,
) -> None:
    """Load Azure applications into Neo4j"""
    ingest_app = """
    UNWIND $tenant_applications_list AS app
    MERGE (i:AzureApplication{id: app.id})
    ON CREATE SET i:AzurePrincipal,
    i.firstseen = timestamp()
    SET i.lastupdated = $update_tag,
        i.object_id = app.id,
        i.app_id = app.appId,
        i.deleted_date_time = app.deletedDateTime,
        i.application_template_id = app.applicationTemplateId,
        i.disabled_by_microsoft_status = app.disabledByMicrosoftStatus,
        i.created_date_time = app.createdDateTime,
        i.display_name = app.displayName,
        i.description = app.description,
        i.group_membership_claims = app.groupMembershipClaims,
        i.identifier_uris = app.identifierUris,
        i.is_device_only_auth_supported = app.isDeviceOnlyAuthSupported,
        i.is_fallback_public_client = app.isFallbackPublicClient,
        i.notes = app.notes,
        i.publisher_domain = app.publisherDomain,
        i.sign_in_audience = app.signInAudience,
        i.tags = app.tags,
        i.api = app.api,
        i.app_roles = app.appRoles,
        i.info = app.info,
        i.key_credentials = app.keyCredentials,
        i.password_credentials = app.passwordCredentials,
        i.required_resource_access = app.requiredResourceAccess,
        i.web = app.web,
        i.spa = app.spa,
        i.consolelink = app.consolelink,
        i.region = $region
    WITH i
    MATCH (owner:AzureTenant{id: $tenant_id})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    tx.run(
        ingest_app,
        region="global",
        tenant_applications_list=tenant_applications_list,
        tenant_id=tenant_id,
        createDate=datetime.utcnow(),
        update_tag=update_tag,
    )


def cleanup_tenant_applications(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_applications_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_applications(
    neo4j_session: neo4j.Session,
    credentials: Credentials,
    tenant_id: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    """Sync applications from Microsoft Graph API to neo4j"""
    client = get_default_graph_client(credentials.default_graph_credentials)
    tenant_applications_list = get_tenant_applications_list(client, tenant_id)

    load_tenant_applications(neo4j_session, tenant_id, tenant_applications_list, update_tag)
    cleanup_tenant_applications(neo4j_session, common_job_parameters)


@timeit
def get_tenant_service_accounts_list(client: GraphServiceClient, tenant_id: str) -> List[Dict]:
    """
    List service principals using Microsoft Graph API
    Docs: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list
    """
    try:
        service_principals_response = client.service_principals.get()

        if not service_principals_response or not service_principals_response.value:
            return []

        tenant_service_accounts_list = []
        for account in service_principals_response.value:
            account.id = f"tenants/{tenant_id}/ServiceAccounts/{account.id}"
            account.consolelink = azure_console_link.get_console_link(
                id=account.id,
                app_id=account.appId,
                iam_entity_type='service_principal',
            )
            tenant_service_accounts_list.append(account)

        return tenant_service_accounts_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant service accounts - {e}")
        return []


def _load_tenant_service_accounts_tx(
    tx: neo4j.Transaction,
    tenant_id: str,
    tenant_service_accounts_list: List[Dict],
    update_tag: int,
) -> None:
    """Load Azure service principals into Neo4j"""
    ingest_app = """
    UNWIND $tenant_service_accounts_list AS account
    MERGE (i:AzureServicePrincipal{id: account.id})
    ON CREATE SET i:AzurePrincipal,
    i.firstseen = timestamp()
    SET i.lastupdated = $update_tag,
        i.object_id = account.id,
        i.deleted_date_time = account.deletedDateTime,
        i.account_enabled = account.accountEnabled,
        i.alternative_names = account.alternativeNames,
        i.app_display_name = account.appDisplayName,
        i.app_description = account.appDescription,
        i.app_id = account.appId,
        i.application_template_id = account.applicationTemplateId,
        i.app_owner_organization_id = account.appOwnerOrganizationId,
        i.app_role_assignment_required = account.appRoleAssignmentRequired,
        i.created_date_time = account.createdDateTime,
        i.description = account.description,
        i.disabled_by_microsoft_status = account.disabledByMicrosoftStatus,
        i.display_name = account.displayName,
        i.homepage = account.homepage,
        i.login_url = account.loginUrl,
        i.logout_url = account.logoutUrl,
        i.notes = account.notes,
        i.notification_email_addresses = account.notificationEmailAddresses,
        i.preferred_single_sign_on_mode = account.preferredSingleSignOnMode,
        i.preferred_token_signing_key_thumbprint = account.preferredTokenSigningKeyThumbprint,
        i.reply_urls = account.replyUrls,
        i.service_principal_names = account.servicePrincipalNames,
        i.service_principal_type = account.servicePrincipalType,
        i.sign_in_audience = account.signInAudience,
        i.tags = account.tags,
        i.token_encryption_key_id = account.tokenEncryptionKeyId,
        i.saml_single_sign_on_settings = account.samlSingleSignOnSettings,
        i.add_ins = account.addIns,
        i.app_roles = account.appRoles,
        i.info = account.info,
        i.key_credentials = account.keyCredentials,
        i.oauth2_permission_scopes = account.oauth2PermissionScopes,
        i.password_credentials = account.passwordCredentials,
        i.resource_specific_application_permissions = account.resourceSpecificApplicationPermissions,
        i.verified_publisher = account.verifiedPublisher,
        i.consolelink = account.consolelink,
        i.region = $region
    WITH i
    MATCH (owner:AzureTenant{id: $tenant_id})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    tx.run(
        ingest_app,
        region="global",
        tenant_service_accounts_list=tenant_service_accounts_list,
        tenant_id=tenant_id,
        createDate=datetime.utcnow(),
        update_tag=update_tag,
    )


def cleanup_tenant_service_accounts(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_service_accounts_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_service_accounts(
    neo4j_session: neo4j.Session,
    credentials: Credentials,
    tenant_id: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    """Sync service principals from Microsoft Graph API to neo4j"""
    client = get_default_graph_client(credentials.default_graph_credentials)
    tenant_service_accounts_list = get_tenant_service_accounts_list(client, tenant_id)
    load_tenant_service_accounts(neo4j_session, tenant_id, tenant_service_accounts_list, update_tag)
    cleanup_tenant_service_accounts(neo4j_session, common_job_parameters)


@timeit
def get_tenant_domains_list(client: GraphServiceClient, tenant_id: str) -> List[Dict]:
    """
    List domains using Microsoft Graph API
    Docs: https://learn.microsoft.com/en-us/graph/api/domain-list
    """
    try:
        domains_response = client.domains.get()

        if not domains_response or not domains_response.value:
            return []

        tenant_domains_list = []
        for domain in domains_response.value:
            domain.id = f"tenants/{tenant_id}/domains/{domain.id}"
            domain.consolelink = azure_console_link.get_console_link(
                id=domain.id,
                iam_entity_type='domain',
            )
            tenant_domains_list.append(domain)

        return tenant_domains_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tenant domains - {e}")
        return []


def _load_tenant_domains_tx(
    tx: neo4j.Transaction,
    tenant_id: str,
    tenant_domains_list: List[Dict],
    update_tag: int,
) -> None:
    """Load Azure domains into Neo4j"""
    ingest_domain = """
    UNWIND $tenant_domains_list AS domain
    MERGE (i:AzureDomain{id: domain.id})
    ON CREATE SET i:AzurePrincipal,
    i.firstseen = timestamp()
    SET i.lastupdated = $update_tag,
        i.authentication_type = domain.authenticationType,
        i.availability_status = domain.availabilityStatus,
        i.is_admin_managed = domain.isAdminManaged,
        i.is_default = domain.isDefault,
        i.is_initial = domain.isInitial,
        i.is_root = domain.isRoot,
        i.is_verified = domain.isVerified,
        i.supported_services = domain.supportedServices,
        i.password_validity_period_in_days = domain.passwordValidityPeriodInDays,
        i.password_notification_window_in_days = domain.passwordNotificationWindowInDays,
        i.state = domain.state,
        i.consolelink = domain.consolelink,
        i.region = $region
    WITH i
    MATCH (owner:AzureTenant{id: $tenant_id})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    tx.run(
        ingest_domain,
        region="global",
        tenant_domains_list=tenant_domains_list,
        tenant_id=tenant_id,
        createDate=datetime.utcnow(),
        update_tag=update_tag,
    )


def cleanup_tenant_domains(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_domains_cleanup.json', neo4j_session, common_job_parameters)


def sync_tenant_domains(
    neo4j_session: neo4j.Session,
    credentials: Credentials,
    tenant_id: str,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    """Sync domains from Microsoft Graph API to neo4j"""
    client = get_default_graph_client(credentials.default_graph_credentials)
    tenant_domains_list = get_tenant_domains_list(client, tenant_id)
    load_tenant_domains(neo4j_session, tenant_id, tenant_domains_list, update_tag)
    cleanup_tenant_domains(neo4j_session, common_job_parameters)


@timeit
def get_roles_list(subscription_id: str, client: AuthorizationManagementClient, common_job_parameters: Dict) -> List[Dict]:
    try:
        role_definitions_list = list(
            map(lambda x: x.as_dict(), client.role_definitions.list(scope=f"/subscriptions/{subscription_id}")),
        )
        for role in role_definitions_list:
            role['consolelink'] = azure_console_link.get_console_link(
                id=role['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
            permissions = []
            for permission in role.get('permissions', []):
                for action in permission.get('actions', []):
                    permissions.append(action)
                for data_action in permission.get('dataActions', []):
                    permissions.append(data_action)
            role['permissions'] = list(set(permissions))

        return role_definitions_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving roles - {e}")
        return []


@timeit
def get_role_assignments(client: AuthorizationManagementClient, common_job_parameters: Dict) -> List[Dict]:
    try:
        role_assignments_list = list(
            map(lambda x: x.as_dict(), client.role_assignments.list()),
        )

        return role_assignments_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving roles - {e}")
        return []


@timeit
def get_managed_identity_list(client: ManagedServiceIdentityClient, subscription_id: str, common_job_parameters: Dict) -> List[Dict]:
    try:
        managed_identity_list = list(
            map(lambda x: x.as_dict(), client.user_assigned_identities.list_by_subscription()),
        )

        for managed_identity in managed_identity_list:
            managed_identity['consolelink'] = azure_console_link.get_console_link(
                id=managed_identity['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
        return managed_identity_list
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving managed identity - {e}")
        return []


def _load_roles_tx(
    tx: neo4j.Transaction, tenant_id: str, roles_list: List[Dict], role_assignments_list: List[Dict], update_tag: int, SUBSCRIPTION_ID: str,
) -> None:
    ingest_role = """
    UNWIND $roles_list AS role
    MERGE (i:AzureRole{id: role.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.name = role.role_name,
    i.consolelink = role.consolelink,
    i.region = $region,
    i.create_date = $createDate
    SET i.lastupdated = $update_tag,
    i.roleName = role.role_name,
    i.permissions = role.permissions,
    i.type = role.type,
    i.role_type = role.role_type
    WITH i,role
    MATCH (t:AzureTenant{id: $tenant_id})
    MERGE (t)-[tr:RESOURCE]->(i)
    ON CREATE SET tr.firstseen = timestamp()
    SET tr.lastupdated = $update_tag
    WITH i,role
    MATCH (sub:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (sub)<-[sr:HAS_ACCESS]-(i)
    ON CREATE SET sr.firstseen = timestamp()
    SET sr.lastupdated = $update_tag
    """

    tx.run(
        ingest_role,
        region="global",
        roles_list=roles_list,
        update_tag=update_tag,
        createDate=datetime.utcnow(),
        tenant_id=tenant_id,
        SUBSCRIPTION_ID=SUBSCRIPTION_ID,
    )

    attach_role = """
    UNWIND $principal_ids AS principal_id
    MATCH (principal:AzurePrincipal{object_id: principal_id})
    WITH principal
    MATCH (i:AzureRole{id: $role})
    WITH i,principal
    MERGE (principal)-[r:ASSUME_ROLE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """
    for role_assignment in role_assignments_list:
        tx.run(
            attach_role,
            role=role_assignment['role_definition_id'],
            principal_ids=role_assignment['principal_id'],
            update_tag=update_tag,
        )


def _load_managed_identities_tx(
    tx: neo4j.Transaction, tenant_id: str, managed_identity_list: List[Dict], update_tag: int,
) -> None:
    ingest_managed_identity = """
    UNWIND $managed_identity_list AS managed_identity
    MERGE (i:AzureManagedIdentity{id: toLower(managed_identity.id)})
    ON CREATE SET i:AzurePrincipal,
    i.firstseen = timestamp()
    SET i.lastupdated = $update_tag,
    i.name = managed_identity.name,
    i.consolelink = managed_identity.consolelink,
    i.location = managed_identity.location,
    i.type = managed_identity.type,
    i.object_id = managed_identity.principal_id,
    i.principal_id = managed_identity.principal_id,
    i.client_id = managed_identity.client_id
    WITH i
    MATCH (t:AzureTenant{id: $tenant_id})
    MERGE (t)-[tr:RESOURCE]->(i)
    ON CREATE SET tr.firstseen = timestamp()
    SET tr.lastupdated = $update_tag
    """

    tx.run(
        ingest_managed_identity,
        managed_identity_list=managed_identity_list,
        update_tag=update_tag,
        tenant_id=tenant_id,
    )


def cleanup_roles(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tenant_roles_cleanup.json', neo4j_session, common_job_parameters)


def cleanup_managed_identities(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_managed_identity_cleanup.json', neo4j_session, common_job_parameters)


def sync_roles(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_authorization_client(credentials.arm_credentials, credentials.subscription_id)
    roles_list = get_roles_list(credentials.subscription_id, client, common_job_parameters)
    role_assignments_list = get_role_assignments(client, common_job_parameters)
    load_roles(neo4j_session, tenant_id, roles_list, role_assignments_list, update_tag, credentials.subscription_id)
    cleanup_roles(neo4j_session, common_job_parameters)


def sync_managed_identity(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    client = get_managed_identity_client(credentials.arm_credentials, credentials.subscription_id)
    managed_identity_list = get_managed_identity_list(client, credentials.subscription_id, common_job_parameters)
    load_managed_identities(neo4j_session, tenant_id, managed_identity_list, update_tag)
    cleanup_managed_identities(neo4j_session, common_job_parameters)


def _set_used_state_tx(
    tx: neo4j.Transaction, tenant_id: str, common_job_parameters: Dict, update_tag: int,
) -> None:
    ingest_role_used = """
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->
    (:AzureTenant{id: $AZURE_TENANT_ID})-[r:RESOURCE]->(n:AzureRole)<-[:ASSUME_ROLE]-(p:AzurePrincipal)
    WHERE n.lastupdated = $update_tag
    SET n.isUsed = $isUsed,
    p.isUsed = $isUsed
    """

    tx.run(
        ingest_role_used,
        WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
        update_tag=update_tag,
        AZURE_TENANT_ID=tenant_id,
        isUsed=True,
    )

    ingest_entity_unused = """
    MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->
    (:AzureTenant{id: $AZURE_TENANT_ID})-[r:RESOURCE]->(n)
    WHERE NOT EXISTS(n.isUsed) AND n.lastupdated = $update_tag
    AND labels(n) IN [['AzureUser'], ['AzureGroup'], ['AzureServiceAccount'], ['AzureRole']]
    SET n.isUsed = $isUsed
    """

    tx.run(
        ingest_entity_unused,
        WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
        update_tag=update_tag,
        AZURE_TENANT_ID=tenant_id,
        isUsed=False,
    )


@timeit
def sync(
    neo4j_session: neo4j.Session, credentials: Credentials, tenant_id: str, update_tag: int,
    common_job_parameters: Dict,
) -> None:
    logger.info("Syncing IAM for Tenant '%s'.", tenant_id)

    common_job_parameters['AZURE_TENANT_ID'] = tenant_id

    try:
        sync_tenant_users(
            neo4j_session, credentials.default_graph_credentials, tenant_id,
            update_tag, common_job_parameters,
        )
        sync_tenant_groups(
            neo4j_session, credentials, tenant_id,
            update_tag, common_job_parameters,
        )
        sync_tenant_applications(
            neo4j_session, credentials.default_graph_credentials,
            tenant_id, update_tag, common_job_parameters,
        )
        sync_tenant_service_accounts(
            neo4j_session, credentials.default_graph_credentials,
            tenant_id, update_tag, common_job_parameters,
        )
        sync_tenant_domains(neo4j_session, credentials.default_graph_credentials, tenant_id, update_tag, common_job_parameters)
        sync_managed_identity(
            neo4j_session, credentials, tenant_id, update_tag, common_job_parameters,
        )

        sync_roles(
            neo4j_session, credentials, tenant_id, update_tag, common_job_parameters,
        )
        set_used_state(neo4j_session, tenant_id, common_job_parameters, update_tag)

    except Exception as ex:
        logger.error(f'exception from IAM - {ex}', exc_info=True, stack_info=True)
