import json
import logging
from typing import Dict
from typing import List

import time
import neo4j
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource
from cloudconsolelink.clouds.gcp import GCPLinker

from cartography.util import run_cleanup_job
from . import label
from cartography.util import timeit
logger = logging.getLogger(__name__)
gcp_console_link = GCPLinker()


def set_used_state(session: neo4j.Session, project_id: str, common_job_parameters: Dict, update_tag: int) -> None:
    session.write_transaction(_set_used_state_tx, project_id, common_job_parameters, update_tag)


@timeit
def get_users(admin: Resource) -> List[Dict]:
    users = []
    try:
        req = admin.users().list()
        while req is not None:
            res = req.execute()
            page = res.get('users', [])
            users.extend(page)
            req = admin.users().list_next(previous_request=req, previous_response=res)

        return users
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve users due to permissions issue. Code: %s, Message: %s"
                ), err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def get_customer(admin: Resource, customer_id: str) -> Dict:
    try:
        req = admin.customers().get(customer=customer_id)
        return req.execute()
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve customer due to permissions issue. Code: %s, Message: %s"
                ), err['code'], err['message'],
            )
            return {}
        else:
            raise


@timeit
def get_domains(admin: Resource, customer_id: str, project_id: str) -> List[Dict]:
    domains = []
    try:
        req = admin.domains().list(customer=customer_id)
        while req is not None:
            res = req.execute()
            page = res.get('domains', [])
            domains.extend(page)
        for domain in domains:
            domain["id"] = f"projects/{project_id}/domains/{domain.get('domainName',None)}"
        return domains
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve domains due to permissions issue. Code: %s, Message: %s"
                ), err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def get_groups(admin: Resource) -> List[Dict]:
    groups = []
    try:
        req = admin.groups().list()
        while req is not None:
            res = req.execute()
            page = res.get('groups', [])
            groups.extend(page)
            req = admin.groups().list_next(previous_request=req, previous_response=res)
        return groups
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve groups due to permissions issue. Code: %s, Message: %s"
                ), err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def get_service_accounts(iam: Resource, project_id: str) -> List[Dict]:
    service_accounts: List[Dict] = []
    try:
        req = iam.projects().serviceAccounts().list(name=f'projects/{project_id}')
        while req is not None:
            res = req.execute()
            page = res.get('accounts', [])
            service_accounts.extend(page)
            req = iam.projects().serviceAccounts().list_next(previous_request=req, previous_response=res)
        return service_accounts
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve service accounts on project %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_service_accounts(service_accounts: List[Dict], project_id: str) -> List[Dict]:
    for account in service_accounts:
        account['firstName'] = account['name'].split('@')[0]
        account['id'] = account['name']
        account['consolelink'] = gcp_console_link.get_console_link(
            resource_name='service_account', project_id=project_id, service_account_unique_id=account['uniqueId'])
    return service_accounts


@timeit
def get_service_account_keys(iam: Resource, project_id: str, service_account: Dict) -> List[Dict]:
    service_keys: List[Dict] = []
    try:
        res = iam.projects().serviceAccounts().keys().list(name=service_account['name']).execute()
        keys = res.get('keys', [])
        for key in keys:
            key['id'] = key['name'].split('/')[-1]
            key['serviceaccount'] = service_account['name']
            key['consolelink'] = gcp_console_link.get_console_link(
                resource_name='service_account_key', project_id=project_id, service_account_unique_id=service_account['uniqueId'])

        service_keys.extend(keys)

        return service_keys
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve Keys on project %s & account %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, service_account['name'], err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def get_roles(iam: Resource, project_id: str) -> List[Dict]:
    roles: List[Dict] = []
    try:
        req = iam.roles().list(view="FULL")
        while req is not None:
            res = req.execute()
            page = res.get('roles', [])
            roles.extend(page)
            req = iam.roles().list_next(previous_request=req, previous_response=res)
        return roles
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve role on project %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def get_project_roles(iam: Resource, project_id: str) -> List[Dict]:
    roles: List[Dict] = []
    try:
        req = iam.projects().roles().list(parent=f'projects/{project_id}', view="FULL")
        while req is not None:
            res = req.execute()
            page = res.get('roles', [])
            roles.extend(page)
            req = iam.projects().roles().list_next(previous_request=req, previous_response=res)
        return roles
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve role on project %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_roles(roles_list: List[Dict], project_id: str) -> List[Dict]:
    for role in roles_list:
        role['id'] = get_role_id(role['name'], project_id)
        role['consolelink'] = gcp_console_link.get_console_link(
            resource_name='iam_role', project_id=project_id, role_id=role['name'])
    return roles_list


@timeit
def get_role_id(role_name: str, project_id: str) -> str:
    if role_name.startswith('organizations/'):
        return role_name

    elif role_name.startswith('projects/'):
        return role_name

    elif role_name.startswith('roles/'):
        return f'projects/{project_id}/roles/{role_name}'
    return ''


@timeit
def get_policy_bindings(crm: Resource, project_id: str) -> List[Dict]:
    try:
        req = crm.projects().getIamPolicy(resource=project_id, body={'options': {'requestedPolicyVersion': 3}})
        res = req.execute()

        if res.get('bindings'):
            return res['bindings']

        return []
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve policy bindings on project %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


def transform_bindings(bindings: Dict, project_id: str) -> tuple:
    users = []
    groups = []
    domains = []
    service_account = []
    entity_list = []
    public_access = False
    for binding in bindings:
        for member in binding['members']:
            if member.startswith('allUsers') or member.startswith('allAuthenticatedUsers'):
                public_access = True
            else:
                if member.startswith('user:'):
                    usr = member[len('user:'):]
                    users.append({
                        "id": f'projects/{project_id}/users/{usr}',
                        "email": usr,
                        "name": usr.split("@")[0],
                    })

                elif member.startswith('group:'):
                    grp = member[len('group:'):]
                    groups.append({
                        "id": f'projects/{project_id}/groups/{grp}',
                        "email": grp,
                        "name": grp.split('@')[0],
                    })

                elif member.startswith('domain:'):
                    dmn = member[len('domain:'):]
                    domains.append({
                        "id": f'projects/{project_id}/domains/{dmn}',
                        "email": dmn,
                        "name": dmn,
                    })

                elif member.startswith('serviceAccount:'):
                    sac = member[len('serviceAccount:'):]
                    service_account.append({
                        "id": f'projects/{project_id}/service_account/{sac}',
                        "email": sac,
                        "name": sac,
                    })

    entity_list.extend(users)
    entity_list.extend(groups)
    entity_list.extend(domains)
    entity_list.extend(service_account)
    # return (
    #     [dict(s) for s in {frozenset(d.items()) for d in users}],
    #     [dict(s) for s in {frozenset(d.items()) for d in groups}],
    #     [dict(s) for s in {frozenset(d.items()) for d in domains}],
    # )
    return entity_list, public_access


@timeit
def load_service_accounts(
    neo4j_session: neo4j.Session,
    service_accounts: List[Dict], project_id: str, gcp_update_tag: int,


) -> None:
    ingest_service_accounts = """
    UNWIND {service_accounts_list} AS sa
    MERGE (u:GCPServiceAccount{id: sa.id})
    ON CREATE SET u:GCPPrincipal, u.firstseen = timestamp()
    SET u.name = sa.name, u.displayname = sa.displayName,
    u.email = sa.email,
    u.consolelink = sa.consolelink,
    u.region = {region},
    u.disabled = sa.disabled, u.serviceaccountid = sa.uniqueId,
    u.lastupdated = {gcp_update_tag}
    WITH u
    MATCH (p:GCPProject{id: {project_id}})
    MERGE (p)-[r:RESOURCE]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_service_accounts,
        service_accounts_list=service_accounts,
        project_id=project_id,
        region="global",
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_service_accounts(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_service_accounts_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_service_account_keys(
    neo4j_session: neo4j.Session, service_account_keys: List[Dict],
    service_account: str, gcp_update_tag: int,
) -> None:
    ingest_service_accounts = """
    UNWIND {service_account_keys_list} AS sa
    MERGE (u:GCPServiceAccountKey{id: sa.id})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name=sa.name, u.serviceaccountid={serviceaccount},
    u.region = {region},
    u.keytype = sa.keyType, u.origin = sa.keyOrigin,
    u.consolelink = sa.consolelink,
    u.algorithm = sa.keyAlgorithm, u.validbeforetime = sa.validBeforeTime,
    u.validaftertime = sa.validAfterTime, u.lastupdated = {gcp_update_tag}
    WITH u, sa
    MATCH (d:GCPServiceAccount{id: sa.serviceaccount})
    MERGE (d)-[r:HAS_KEY]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_service_accounts,
        service_account_keys_list=service_account_keys,
        serviceaccount=service_account,
        region="global",
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_service_account_keys(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_service_account_keys_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_roles(neo4j_session: neo4j.Session, roles: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_roles = """
    UNWIND {roles_list} AS d
    MERGE (u:GCPRole{id: d.id})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name = d.name, u.title = d.title,
    u.region = {region},
    u.description = d.description, u.deleted = d.deleted,
    u.consolelink = d.consolelink,
    u.permissions = d.includedPermissions, u.roleid = d.id,
    u.lastupdated = {gcp_update_tag}
    WITH u
    MATCH (p:GCPProject{id: {project_id}})
    MERGE (p)-[r:RESOURCE]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_roles,
        roles_list=roles,
        region="global",
        project_id=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_roles(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_roles_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_customers(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.write_transaction(_load_customers_tx, data_list, project_id, update_tag)


@timeit
def _load_customers_tx(tx: neo4j.Transaction, customers: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_customers = """
    UNWIND {customers} as cst
        MERGE (customer:GCPcustomer{id:cst.id})
        ON CREATE SET
            customer.firstseen = timestamp()
        SET
            customer.customerDomain = cst.customerDomain,
            customer.kind = cst.kind,
            customer.region = {region},
            customer.alternateEmail = cst.alternateEmail,
            customer.customerCreationTime = cst.customerCreationTime,
            customer.phoneNumber = cst.phoneNumber,
            customer.lastupdated = {gcp_update_tag}
        WITH customer, cst
        MATCH (p:GCPProject{id: {project_id}})
        MERGE (p)-[r:RESOURCE]->(customer)
        ON CREATE SET
            r.firstseen = timestamp()
        SET r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_customers,
        customers=customers,
        project_id=project_id,
        region="global",
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_customers(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_customers_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_users(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.write_transaction(_load_users_tx, data_list, project_id, update_tag)


@timeit
def _load_users_tx(tx: neo4j.Transaction, users: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_users = """
    UNWIND {users} as usr
    MERGE (user:GCPUser{id:usr.id})
    ON CREATE SET
        user:GCPPrincipal,
        user.firstseen = timestamp()
    SET
        user.id = usr.id,
        user.primaryEmail = usr.primaryEmail,
        user.email = usr.primaryEmail,
        user.isAdmin = usr.isAdmin,
        user.isDelegatedAdmin = usr.isDelegatedAdmin,
        user.agreedToTerms = usr.agreedToTerms,
        user.suspended = usr.suspended,
        user.changePasswordAtNextLogin = usr.changePasswordAtNextLogin,
        user.ipWhitelisted = usr.ipWhitelisted,
        user.fullName = usr.name.fullName,
        user.region = {region},
        user.familyName = usr.name.familyName,
        user.givenName = usr.name.givenName,
        user.isMailboxSetup = usr.isMailboxSetup,
        user.customerId = usr.customerId,
        user.addresses = usr.addresses,
        user.organizations = usr.organizations,
        user.lastLoginTime = usr.lastLoginTime,
        user.suspensionReason = usr.suspensionReason,
        user.creationTime = usr.creationTime,
        user.deletionTime = usr.deletionTime,
        user.gender = usr.gender,
        user.consolelink = {consolelink},
        user.lastupdated = {gcp_update_tag}
    WITH user, usr
    MATCH (p:GCPProject{id: {project_id}})
    MERGE (p)-[r:RESOURCE]->(user)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_users,
        users=users,
        project_id=project_id,
        region="global",
        gcp_update_tag=gcp_update_tag,
        consolelink=f"https://console.cloud.google.com/iam-admin/iam?orgonly=true&project={project_id}&supportedpurview=organizationId",
    )


@timeit
def cleanup_users(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_users_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_groups(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.write_transaction(_load_groups_tx, data_list, project_id, update_tag)


@timeit
def _load_groups_tx(tx: neo4j.Transaction, groups: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_groups = """
    UNWIND {groups} as grp
    MERGE (group:GCPGroup{id:grp.id})
    ON CREATE SET
        group:GCPPrincipal,
        group.firstseen = timestamp()
    SET
        group.id = grp.id,
        group.id = grp.name,
        group.email = grp.email,
        group.region = {region},
        group.adminCreated = grp.adminCreated,
        group.directMembersCount = grp.directMembersCount,
        group.lastupdated = {gcp_update_tag}
    WITH group,grp
    MATCH (p:GCPProject{id: {project_id}})
    MERGE (p)-[r:RESOURCE]->(group)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_groups,
        groups=groups,
        region="global",
        project_id=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_groups(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_groups_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_domains(
    session: neo4j.Session, data_list: List[Dict], customer_id: str, project_id: str, update_tag: int,
) -> None:
    session.write_transaction(_load_domains_tx, data_list, customer_id, project_id, update_tag)


@timeit
def _load_domains_tx(
    tx: neo4j.Transaction, domains: List[Dict], customer_id: str, project_id: str, gcp_update_tag: int,
) -> None:
    ingest_domains = """
    UNWIND {domains} as dmn
    MERGE (domain:GCPDomain{id:dmn.id})
    ON CREATE SET
        domain:GCPPrincipal,
        domain.firstseen = timestamp()
    SET
        domain.verified = dmn.verified,
        domain.creationTime = dmn.creationTime,
        domain.region = {region},
        domain.isPrimary = dmn.isPrimary,
        domain.domainName = dmn.domainName,
        domain.kind = dmn.kind,
        domain.name = dmn.domainName,
        domain.email = dmn.domainName
        domain.lastupdated = {gcp_update_tag}
    WITH domain
    MATCH (p:GCPProject{id: {project_id}})
    MERGE (p)-[r:RESOURCE]->(domain)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    WITH domain
    MATCH (p:GCPCustomer{id: {customer_id}})
    MERGE (p)-[r:RESOURCE]->(domain)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """
    tx.run(
        ingest_domains,
        domains=domains,
        region="global",
        project_id=project_id,
        customer_id=customer_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_domains(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_domains_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_bindings(neo4j_session: neo4j.Session, bindings: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    for binding in bindings:
        role_id = get_role_id(binding['role'], project_id)

        for member in binding['members']:
            if member.startswith('user:'):
                attach_role_to_user(
                    neo4j_session, role_id, f"projects/{project_id}/users/{member[len('user:'):]}",
                    project_id, gcp_update_tag,
                )

            elif member.startswith('serviceAccount:'):
                attach_role_to_service_account(
                    neo4j_session,
                    role_id, f"projects/{project_id}/serviceAccounts/{member[len('serviceAccount:'):]}",
                    project_id,
                    gcp_update_tag,
                )

            elif member.startswith('group:'):
                attach_role_to_group(
                    neo4j_session, role_id,
                    f"projects/{project_id}/groups/{member[len('group:'):]}",
                    project_id, gcp_update_tag,
                )

            elif member.startswith('domain:'):
                attach_role_to_domain(
                    neo4j_session, role_id,
                    f"projects/{project_id}/domains/{member[len('domain:'):]}",
                    project_id,
                    gcp_update_tag,
                )


@timeit
def attach_role_to_user(
    neo4j_session: neo4j.Session, role_id: str, user_id: str,
    project_id: str, gcp_update_tag: int,
) -> None:
    ingest_script = """
    MATCH (role:GCPRole{id:{RoleId}})
    MATCH (user:GCPPrincipal{id:{UserId}})
    MERGE (user)-[r:ASSUME_ROLE]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_script,
        RoleId=role_id,
        UserId=user_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def attach_role_to_service_account(
    neo4j_session: neo4j.Session, role_id: str,
    service_account_id: str, project_id: str, gcp_update_tag: int,
) -> None:
    ingest_script = """
    MATCH (role:GCPRole{id:{RoleId}})
    MATCH (sa:GCPPrincipal{id:{saId}})
    MERGE (sa)-[r:ASSUME_ROLE]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_script,
        RoleId=role_id,
        saId=service_account_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def attach_role_to_group(
    neo4j_session: neo4j.Session, role_id: str, group_id: str,
    project_id: str, gcp_update_tag: int,
) -> None:
    ingest_script = """
    MATCH (role:GCPRole{id:{RoleId}})
    MATCH (group:GCPPrincipal{id:{GroupId}})
    MERGE (group)-[r:ASSUME_ROLE]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_script,
        RoleId=role_id,
        GroupId=group_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def attach_role_to_domain(
    neo4j_session: neo4j.Session, role_id: str, domain_id: str,
    project_id: str, gcp_update_tag: int,
) -> None:
    ingest_script = """
    MATCH (role:GCPRole{id:{RoleId}})
    MATCH (domain:GCPPrincipal{id:{DomainId}})
    MERGE (domain)-[r:ASSUME_ROLE]->(role)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_script,
        RoleId=role_id,
        DomainId=domain_id,
        gcp_update_tag=gcp_update_tag,
    )


def _set_used_state_tx(
    tx: neo4j.Transaction, project_id: str, common_job_parameters: Dict, update_tag: int,
) -> None:
    ingest_role_used = """
    MATCH (:CloudanixWorkspace{id: {WORKSPACE_ID}})-[:OWNER]->
    (:GCPProject{id: {GCP_PROJECT_ID}})-[:RESOURCE]->(n:GCPRole)
    WHERE (n)<-[:ASSUME_ROLE]-() AND n.lastupdated = {update_tag}
    SET n.isUsed = {isUsed}
    """

    tx.run(
        ingest_role_used,
        WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
        update_tag=update_tag,
        GCP_PROJECT_ID=project_id,
        isUsed=True,
    )

    ingest_entity_used = """
    MATCH (:CloudanixWorkspace{id: {WORKSPACE_ID}})-[:OWNER]->
    (:GCPProject{id: {GCP_PROJECT_ID}})-[:RESOURCE]->(n)
    WHERE ()<-[:ASSUME_ROLE]-(n) AND n.lastupdated = {update_tag}
    AND labels(n) IN [['GCPCustomer'], ['GCPDomain'], ['GCPGroup'], ['GCPServiceAccount'], ['GCPUser']]
    SET n.isUsed = {isUsed}
    """

    tx.run(
        ingest_entity_used,
        WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
        update_tag=update_tag,
        GCP_PROJECT_ID=project_id,
        isUsed=True,
    )

    ingest_entity_unused = """
    MATCH (:CloudanixWorkspace{id: {WORKSPACE_ID}})-[:OWNER]->
    (:GCPProject{id: {GCP_PROJECT_ID}})-[:RESOURCE]->(n)
    WHERE NOT EXISTS(n.isUsed) AND n.lastupdated = {update_tag}
    AND labels(n) IN [['GCPCustomer'], ['GCPDomain'], ['GCPGroup'], ['GCPServiceAccount'], ['GCPUser'], ['GCPRole']]
    SET n.isUsed = {isUsed}
    """

    tx.run(
        ingest_entity_unused,
        WORKSPACE_ID=common_job_parameters['WORKSPACE_ID'],
        update_tag=update_tag,
        GCP_PROJECT_ID=project_id,
        isUsed=False,
    )


@timeit
def sync(
    neo4j_session: neo4j.Session, iam: Resource, crm: Resource, admin: Resource,
    project_id: str, gcp_update_tag: int, common_job_parameters: Dict
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing IAM for project '%s', at %s.", project_id, tic)

    service_accounts_list = get_service_accounts(iam, project_id)

    if common_job_parameters.get('pagination', {}).get('iam', None):
        pageNo = common_job_parameters.get("pagination", {}).get("iam", None)["pageNo"]
        pageSize = common_job_parameters.get("pagination", {}).get("iam", None)["pageSize"]
        totalPages = len(service_accounts_list) / pageSize
        if int(totalPages) != totalPages:
            totalPages = totalPages + 1
        totalPages = int(totalPages)
        if pageNo < totalPages or pageNo == totalPages:
            logger.info(f'pages process for iam service_accounts {pageNo}/{totalPages} pageSize is {pageSize}')
        page_start = (common_job_parameters.get('pagination', {}).get('iam', {})[
                      'pageNo'] - 1) * common_job_parameters.get('pagination', {}).get('iam', {})['pageSize']
        page_end = page_start + common_job_parameters.get('pagination', {}).get('iam', {})['pageSize']
        if page_end > len(service_accounts_list) or page_end == len(service_accounts_list):
            service_accounts_list = service_accounts_list[page_start:]
        else:
            has_next_page = True
            service_accounts_list = service_accounts_list[page_start:page_end]
            common_job_parameters['pagination']['iam']['hasNextPage'] = has_next_page

    service_accounts_list = transform_service_accounts(service_accounts_list, project_id)
    load_service_accounts(neo4j_session, service_accounts_list, project_id, gcp_update_tag)

    for service_account in service_accounts_list:
        service_account_keys = get_service_account_keys(iam, project_id, service_account)
        load_service_account_keys(neo4j_session, service_account_keys, service_account['name'], gcp_update_tag)

    cleanup_service_accounts(neo4j_session, common_job_parameters)
    label.sync_labels(neo4j_session, service_accounts_list, gcp_update_tag,
                      common_job_parameters, 'service accounts', 'GCPServiceAccount')

    roles_list = get_roles(iam, project_id)
    custom_roles_list = get_project_roles(iam, project_id)
    roles_list.extend(custom_roles_list)

    if common_job_parameters.get('pagination', {}).get('iam', None):
        pageNo = common_job_parameters.get("pagination", {}).get("iam", None)["pageNo"]
        pageSize = common_job_parameters.get("pagination", {}).get("iam", None)["pageSize"]
        totalPages = len(roles_list) / pageSize
        if int(totalPages) != totalPages:
            totalPages = totalPages + 1
        totalPages = int(totalPages)
        if pageNo < totalPages or pageNo == totalPages:
            logger.info(f'pages process for iam roles {pageNo}/{totalPages} pageSize is {pageSize}')
        page_start = (common_job_parameters.get('pagination', {}).get('iam', {})[
                      'pageNo'] - 1) * common_job_parameters.get('pagination', {}).get('iam', {})['pageSize']
        page_end = page_start + common_job_parameters.get('pagination', {}).get('iam', {})['pageSize']
        if page_end > len(roles_list) or page_end == len(roles_list):
            roles_list = roles_list[page_start:]
        else:
            has_next_page = True
            roles_list = roles_list[page_start:page_end]
            common_job_parameters['pagination']['iam']['hasNextPage'] = has_next_page

    roles_list = transform_roles(roles_list, project_id)

    load_roles(neo4j_session, roles_list, project_id, gcp_update_tag)
    cleanup_roles(neo4j_session, common_job_parameters)
    label.sync_labels(neo4j_session, roles_list, gcp_update_tag, common_job_parameters, 'roles', 'GCPRole')

    users = get_users(admin)

    if common_job_parameters.get('pagination', {}).get('iam', None):
        pageNo = common_job_parameters.get("pagination", {}).get("iam", None)["pageNo"]
        pageSize = common_job_parameters.get("pagination", {}).get("iam", None)["pageSize"]
        totalPages = len(users) / pageSize
        if int(totalPages) != totalPages:
            totalPages = totalPages + 1
        totalPages = int(totalPages)
        if pageNo < totalPages or pageNo == totalPages:
            logger.info(f'pages process for iam users {pageNo}/{totalPages} pageSize is {pageSize}')
        page_start = (common_job_parameters.get('pagination', {}).get('iam', {})[
                      'pageNo'] - 1) * common_job_parameters.get('pagination', {}).get('iam', {})['pageSize']
        page_end = page_start + common_job_parameters.get('pagination', {}).get('iam', {})['pageSize']
        if page_end > len(users) or page_end == len(users):
            users = users[page_start:]
        else:
            has_next_page = True
            users = users[page_start:page_end]
            common_job_parameters['pagination']['iam']['hasNextPage'] = has_next_page

    customer_ids = []
    for user in users:
        customer_ids.append(get_customer(user.get('customerId')))

    customer_ids = list(set(customer_ids))
    customer_ids.sort()

    customers = []
    for customer_id in customer_ids:
        customers.append(get_customer(customer_id))

    load_customers(neo4j_session, customers, project_id, gcp_update_tag)
    cleanup_customers(neo4j_session, common_job_parameters)

    load_users(neo4j_session, users, project_id, gcp_update_tag)
    cleanup_users(neo4j_session, common_job_parameters)
    label.sync_labels(neo4j_session, users, gcp_update_tag, common_job_parameters, 'users', 'GCPUser')

    for customer in customers:
        domains = get_domains(admin, customer, project_id)
        load_domains(neo4j_session, domains, customer.get('id'), project_id, gcp_update_tag)

    cleanup_domains(neo4j_session, common_job_parameters)

    groups = get_groups(admin)

    if common_job_parameters.get('pagination', {}).get('iam', None):
        pageNo = common_job_parameters.get("pagination", {}).get("iam", None)["pageNo"]
        pageSize = common_job_parameters.get("pagination", {}).get("iam", None)["pageSize"]
        totalPages = len(groups) / pageSize
        if int(totalPages) != totalPages:
            totalPages = totalPages + 1
        totalPages = int(totalPages)
        if pageNo < totalPages or pageNo == totalPages:
            logger.info(f'pages process for iam groups {pageNo}/{totalPages} pageSize is {pageSize}')
        page_start = (common_job_parameters.get('pagination', {}).get('iam', {})[
                      'pageNo'] - 1) * common_job_parameters.get('pagination', {}).get('iam', {})['pageSize']
        page_end = page_start + common_job_parameters.get('pagination', {}).get('iam', {})['pageSize']
        if page_end > len(groups) or page_end == len(groups):
            groups = groups[page_start:]
        else:
            has_next_page = True
            groups = groups[page_start:page_end]
            common_job_parameters['pagination']['iam']['hasNextPage'] = has_next_page
    load_groups(neo4j_session, groups, project_id, gcp_update_tag)
    cleanup_groups(neo4j_session, common_job_parameters)
    label.sync_labels(neo4j_session, groups, gcp_update_tag, common_job_parameters, 'groups', 'GCPGroup')

    if common_job_parameters.get('pagination', {}).get('iam', None):
        if not common_job_parameters.get('pagination', {}).get('iam', {}).get('hasNextPage', False):
            bindings = get_policy_bindings(crm, project_id)
            # users_from_bindings, groups_from_bindings, domains_from_bindings = transform_bindings(bindings, project_id)

            load_bindings(neo4j_session, bindings, project_id, gcp_update_tag)
            set_used_state(neo4j_session, project_id, common_job_parameters, gcp_update_tag)
    else:
        bindings = get_policy_bindings(crm, project_id)
        # users_from_bindings, groups_from_bindings, domains_from_bindings = transform_bindings(bindings, project_id)

        load_bindings(neo4j_session, bindings, project_id, gcp_update_tag)
        set_used_state(neo4j_session, project_id, common_job_parameters, gcp_update_tag)

    toc = time.perf_counter()
    logger.info(f"Time to process IAM: {toc - tic:0.4f} seconds")
