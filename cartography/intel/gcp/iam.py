import json
import logging
from typing import Dict
from typing import List

import neo4j
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from cartography.util import run_cleanup_job
from cartography.util import timeit
logger = logging.getLogger(__name__)


@timeit
def get_service_accounts(iam: Resource, project_id: str) -> List[Dict]:
    service_accounts: List[Dict] = []
    try:
        req = iam.projects().serviceAccounts().list(name='projects/{}'.format(project_id))
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
                    "Could not retrieve IAM Policy on project %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_service_accounts(service_accounts: List[Dict]) -> List[Dict]:
    for account in service_accounts:
        account['firstName'] = account['name'].split('@')[0]

    return service_accounts


@timeit
def get_service_account_keys(iam: Resource, project_id: str, service_account: str) -> List[Dict]:
    service_keys: List[Dict] = []
    try:
        res = iam.projects().serviceAccounts().keys().list(name=service_account).execute()
        keys = res.get('keys', [])
        for key in keys:
            key['id'] = key['name'].split('/')[-1]
            key['serviceaccount'] = service_account

        service_keys.extend(keys)

        return service_keys
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve Keys on project %s & account %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, service_account, err['code'], err['message'],
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
            req = iam.projects().roles().list_next(previous_request=req, previous_response=res)
        return roles
    except HttpError as e:
        err = json.loads(e.content.decode('utf-8'))['error']
        if err['status'] == 'PERMISSION_DENIED':
            logger.warning(
                (
                    "Could not retrieve IAM Policy on project %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def get_project_roles(iam: Resource, project_id: str) -> List[Dict]:
    roles: List[Dict] = []
    try:
        req = iam.projects().roles().list(parent='projects/{}'.format(project_id), view="FULL")
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
                    "Could not retrieve IAM Policy on project %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return []
        else:
            raise


@timeit
def transform_roles(roles_list: List[Dict], project_id: str) -> List[Dict]:
    for role in roles_list:
        role['id'] = get_role_id(role['name'], project_id)

    return roles_list


@timeit
def get_role_id(role_name: str, project_id: str) -> str:
    if role_name.startswith('organizations/'):
        return role_name

    elif role_name.startswith('projects/'):
        return role_name

    elif role_name.startswith('roles/'):
        return f'projects/{project_id}/roles/{role_name}'


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
                    "Could not retrieve IAM Policy on project %s due to permissions issue. Code: %s, Message: %s"
                ), project_id, err['code'], err['message'],
            )
            return {}
        else:
            raise


def transform_bindings(bindings, project_id):
    users = []
    groups = []
    domains = []

    for binding in bindings:
        for member in binding['members']:
            if member.startswith('user:'):
                usr = member[len('user:'):]
                users.append({
                    "id": f'projects/{project_id}/users/{usr}',
                    "email": usr,
                    "name": usr.split("@")[0]
                })

            elif member.startswith('group:'):
                grp = member[len('group:'):]
                groups.append({
                    "id": f'projects/{project_id}/groups/{grp}',
                    "email": grp,
                    "name": grp.split('@')[0]
                })

            elif member.startswith('domain:'):
                dmn = member[len('domain:'):]
                domains.append({
                    "id": f'projects/{project_id}/domains/{dmn}',
                    "email": dmn,
                    "name": dmn
                })

    return [dict(s) for s in set(frozenset(d.items()) for d in users)], [dict(s) for s in set(frozenset(d.items()) for d in groups)], [dict(s) for s in set(frozenset(d.items()) for d in domains)]


@timeit
def load_users(neo4j_session: neo4j.Session, users: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_users = """
    UNWIND {users_list} AS usr
    MERGE (u:GCPUser{id: usr.id})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name = usr.name, u.email = usr.email,
    u.userid = usr.id, u.lastupdated = {gcp_update_tag}
    WITH u, usr
    MATCH (d:GCPProject{id: {project_id}})
    MERGE (d)-[r:RESOURCE]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_users,
        users_list=users,
        project_id=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_users(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_users_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_service_accounts(neo4j_session: neo4j.Session, service_accounts: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_service_accounts = """
    UNWIND {service_accounts_list} AS sa
    MERGE (u:GCPServiceAccount{id: sa.name})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name = sa.firstName, u.displayname = sa.displayName,
    u.email = sa.email, u.description = sa.description,
    u.disabled = sa.disabled, u.serviceaccountid = sa.uniqueId,
    u.lastupdated = {gcp_update_tag}
    WITH u, sa
    MATCH (d:GCPProject{id: {project_id}})
    MERGE (d)-[r:RESOURCE]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_service_accounts,
        service_accounts_list=service_accounts,
        project_id=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_service_accounts(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_service_accounts_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_service_account_keys(neo4j_session: neo4j.Session, service_account_keys: List[Dict], service_account: str, gcp_update_tag: int) -> None:
    ingest_service_accounts = """
    UNWIND {service_account_keys_list} AS sa
    MERGE (u:GCPServiceAccountKey{id: sa.id})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name=sa.name, u.serviceaccountid={serviceaccount},
    u.keytype = sa.keyType, u.origin = sa.keyOrigin,
    u.algorithm = sa.keyAlgorithm, u.validbeforetime = sa.validBeforeTime,
    u.validaftertime = sa.validAfterTime, u.lastupdated = {gcp_update_tag}
    WITH u, sa
    MATCH (d:GCPServiceAccount{id: {serviceaccount}})
    MERGE (d)-[r:HAS_KEY]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_service_accounts,
        service_account_keys_list=service_account_keys,
        serviceaccount=service_account,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_service_account_keys(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_service_account_keys_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_groups(neo4j_session: neo4j.Session, groups: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_groups = """
    UNWIND {groups_list} AS g
    MERGE (u:GCPGroup{id: g.id})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name = g.name, u.email=g.email,
    u.groupid = g.id, u.lastupdated = {gcp_update_tag}
    WITH u, g
    MATCH (d:GCPProject{id: {project_id}})
    MERGE (d)-[r:RESOURCE]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_groups,
        groups_list=groups,
        project_id=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_groups(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_groups_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_domains(neo4j_session: neo4j.Session, domains: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_domains = """
    UNWIND {domains_list} AS d
    MERGE (u:GCPDomain{id: d.id})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name = d.name, u.domainid = d.id,
    u.lastupdated = {gcp_update_tag}
    WITH u, d
    MATCH (d:GCPProject{id: {project_id}})
    MERGE (d)-[r:RESOURCE]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_domains,
        domains_list=domains,
        project_id=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_domains(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_domains_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_roles(neo4j_session: neo4j.Session, roles: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    ingest_roles = """
    UNWIND {roles_list} AS d
    MERGE (u:GCPRole{id: d.id})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name = d.name, u.title = d.title,
    u.description = d.description, u.deleted = d.deleted,
    u.permissions = d.includedPermissions, u.roleid = d.id,
    u.lastupdated = {gcp_update_tag}
    WITH u, d
    MATCH (d:GCPProject{id: {project_id}})
    MERGE (d)-[r:RESOURCE]->(u)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {gcp_update_tag}
    """

    neo4j_session.run(
        ingest_roles,
        roles_list=roles,
        project_id=project_id,
        gcp_update_tag=gcp_update_tag,
    )


@timeit
def cleanup_roles(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_iam_roles_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def load_bindings(neo4j_session: neo4j.Session, bindings: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    for binding in bindings:
        role_id = get_role_id(binding['role'], project_id)

        for member in binding['members']:
            if member.startswith('user:'):
                attach_role_to_user(neo4j_session, role_id, f"projects/{project_id}/users/{member[len('user:'):]}", project_id, gcp_update_tag)

            elif member.startswith('serviceAccount:'):
                attach_role_to_service_account(neo4j_session, role_id, f"projects/{project_id}/serviceAccounts/{member[len('serviceAccount:'):]}", project_id, gcp_update_tag)

            elif member.startswith('group:'):
                attach_role_to_group(neo4j_session, role_id, f"projects/{project_id}/groups/{member[len('group:'):]}", project_id, gcp_update_tag)

            elif member.startswith('domain:'):
                attach_role_to_domain(neo4j_session, role_id, f"projects/{project_id}/domains/{member[len('domain:'):]}", project_id, gcp_update_tag)


@timeit
def attach_role_to_user(neo4j_session: neo4j.Session, role_id: str, user_id: str, project_id: str, gcp_update_tag: int) -> None:
    ingest_script = """
    MATCH (role:GCPRole{id:{RoleId}})

    MERGE (user:GCPUser{id:{UserId}})

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
def attach_role_to_service_account(neo4j_session: neo4j.Session, role_id: str, service_account_id: str, project_id: str, gcp_update_tag: int) -> None:
    ingest_script = """
    MATCH (role:GCPRole{id:{RoleId}})

    MERGE (sa:GCPServiceAccount{id:{saId}})

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
def attach_role_to_group(neo4j_session: neo4j.Session, role_id: str, group_id: str, project_id: str, gcp_update_tag: int) -> None:
    ingest_script = """
    MATCH (role:GCPRole{id:{RoleId}})

    MERGE (group:GCPGroup{id:{GroupId}})

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
def attach_role_to_domain(neo4j_session: neo4j.Session, role_id: str, domain_id: str, project_id: str, gcp_update_tag: int) -> None:
    ingest_script = """
    MATCH (role:GCPRole{id:{RoleId}})

    MERGE (domain:GCPDomain{id:{DomainId}})

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


@timeit
def sync(
    neo4j_session: neo4j.Session, iam: Resource, crm: Resource, project_id: str, gcp_update_tag: int,
    common_job_parameters: Dict, regions: List[str],
) -> None:
    logger.info("Syncing IAM objects for project %s.", project_id)

    service_accounts_list = get_service_accounts(iam, project_id)
    service_accounts_list = transform_service_accounts(service_accounts_list)
    load_service_accounts(neo4j_session, service_accounts_list, project_id, gcp_update_tag)
    cleanup_service_accounts(neo4j_session, common_job_parameters)

    for service_account in service_accounts_list:
        service_account_keys = get_service_account_keys(iam, project_id, service_account['name'])
        load_service_account_keys(neo4j_session, service_account_keys, service_account['name'], gcp_update_tag)

    cleanup_service_account_keys(neo4j_session, common_job_parameters)

    roles_list = get_roles(iam, project_id)
    custom_roles_list = get_project_roles(iam, project_id)
    roles_list.extend(custom_roles_list)

    roles_list = transform_roles(roles_list, project_id)

    load_roles(neo4j_session, roles_list, project_id, gcp_update_tag)
    cleanup_roles(neo4j_session, common_job_parameters)

    bindings = get_policy_bindings(crm, project_id)

    users, groups, domains = transform_bindings(bindings, project_id)

    load_users(neo4j_session, users, project_id, gcp_update_tag)

    load_groups(neo4j_session, groups, project_id, gcp_update_tag)

    load_domains(neo4j_session, domains, project_id, gcp_update_tag)

    load_bindings(neo4j_session, bindings, project_id, gcp_update_tag)

    cleanup_users(neo4j_session, common_job_parameters)
    cleanup_groups(neo4j_session, common_job_parameters)
    cleanup_domains(neo4j_session, common_job_parameters)