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
def get_projects(api_url: str, organization_name: str, token: str) -> List[Dict]:
    """
    Retrieve a list of projects from the given Azure DevOps organization.
    """
    url = f"{api_url}/{organization_name}/_apis/projects?api-version=7.1-preview.4"
    response = call_azure_devops_api(url, token)
    return response.get("value", []) if response else []


@timeit
def load_projects(
    neo4j_session: neo4j.Session,
    project_data: List[Dict],
    organization_name: str,
    common_job_parameters: Dict[str, Any],
) -> None:
    query = """
    UNWIND $ProjectData as project

    MERGE (p:AzureDevOpsProject{id: project.id})
    ON CREATE SET p.firstseen = timestamp()
    SET p.name = project.name,
        p.url = project.url,
        p.state = project.state,
        p.revision = project.revision,
        p.visibility = project.visibility,
        p.lastupdatetime = project.lastUpdateTime,
        p.lastupdated = $UpdateTag
    WITH p

    MATCH (org:AzureDevOpsOrganization{id: $OrganizationName})
    MERGE (org)-[r:HAS_PROJECT]->(p)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """
    neo4j_session.run(
        query,
        ProjectData=project_data,
        OrganizationName=organization_name,
        UpdateTag=common_job_parameters['UPDATE_TAG'],
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_devops_projects_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict[str, Any],
    azure_devops_api_key: str,
    azure_devops_url: str,
    organization: str,
) -> None:
    logger.info("Syncing Azure DevOps Projects")
    projects = get_projects(azure_devops_url, organization, azure_devops_api_key)

    if projects:
        load_projects(neo4j_session, projects, organization, common_job_parameters)
        cleanup(neo4j_session, common_job_parameters) 