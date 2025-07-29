import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j

from cartography.util import run_cleanup_job
from cartography.util import timeit
from .util import call_azure_devops_api

logger = logging.getLogger(__name__)


@timeit
def get_users(api_url: str, organization_name: str, token: str) -> List[Dict]:
    """
    Retrieve a list of users from the given Azure DevOps organization.
    """
    url = f"https://vsaex.dev.azure.com/{organization_name}/_apis/userentitlements?api-version=7.1-preview.3"
    response = call_azure_devops_api(url, token)
    return response.get("items", []) if response else []


@timeit
def load_users(
    neo4j_session: neo4j.Session,
    user_data: List[Dict],
    organization_name: str,
    common_job_parameters: Dict[str, Any],
) -> None:
    query = """
    UNWIND $UserData as user

    MERGE (u:AzureDevOpsUser{id: user.id})
    ON CREATE SET u.firstseen = timestamp()
    SET u.name = user.user.displayName,
        u.principal_name = user.user.principalName,
        u.origin = user.user.origin,
        u.origin_id = user.user.originId,
        u.last_access_date = user.lastAccessedDate,
        u.access_level = user.accessLevel.licensingSource,
        u.status = user.accessLevel.status,
        u.lastupdated = $UpdateTag
    WITH u

    MATCH (org:AzureDevOpsOrganization{id: $OrganizationName})
    MERGE (u)-[r:MEMBER_OF]->(org)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """
    neo4j_session.run(
        query,
        UserData=user_data,
        OrganizationName=organization_name,
        UpdateTag=common_job_parameters['UPDATE_TAG'],
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_devops_members_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict[str, Any],
    azure_devops_api_key: str,
    azure_devops_url: str,
    organization: str,
) -> None:
    logger.info("Syncing Azure DevOps Members")
    users = get_users(azure_devops_url, organization, azure_devops_api_key)
    if users:
        load_users(neo4j_session, users, organization, common_job_parameters)
        cleanup(neo4j_session, common_job_parameters) 