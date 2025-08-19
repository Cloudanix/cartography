import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j

from .util import call_azure_devops_api, validate_project_data
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_projects(api_url: str, organization_name: str, access_token: str) -> List[Dict]:
    """
    Retrieve a list of projects from the given Azure DevOps organization.

    Args:
        api_url: Base Azure DevOps URL (e.g., https://dev.azure.com)
        organization_name: Name of the organization
        access_token: Microsoft Entra ID OAuth access token

    Returns:
        List of project dictionaries or empty list if failed
    """
    url = f"{api_url}/{organization_name}/_apis/projects?api-version=7.1-preview.4"

    logger.debug(f"Fetching projects from: {url}")
    response = call_azure_devops_api(url, access_token)

    if not response:
        logger.warning(
            f"No response received for projects in organization {organization_name}"
        )
        return []

    projects = response.get("value", [])
    # Filter out invalid projects
    valid_projects = [p for p in projects if validate_project_data(p)]

    if len(valid_projects) != len(projects):
        logger.warning(
            f"Filtered out {len(projects) - len(valid_projects)} invalid projects for organization {organization_name}"
        )

    logger.debug(
        f"Retrieved {len(valid_projects)} valid projects for organization {organization_name}"
    )
    return valid_projects


@timeit
def load_projects(
    neo4j_session: neo4j.Session,
    project_data: List[Dict],
    organization_name: str,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Load Azure DevOps project data into Neo4j with comprehensive properties.
    - id: Project ID (unique identifier)
    - name: Project name
    - url: Project URL
    - state: Project state (active, deleted, etc.)
    - revision: Project revision number
    - visibility: Project visibility (private, public)
    - lastUpdateTime: Last update timestamp
    - description: Project description (if available)
    - capabilities: Project capabilities (if available)
    """
    query = """
    UNWIND $ProjectData as project

    MERGE (p:AzureDevOpsProject{id: project.id})
    ON CREATE SET p.firstseen = timestamp()
    ON MATCH SET
        p.lastupdated = $UPDATE_TAG,
        p.name = project.name,
        p.url = project.url,
        p.state = project.state,
        p.revision = project.revision,
        p.visibility = project.visibility,
        p.lastupdatetime = project.lastUpdateTime,
        p.description = project.description,
        p.capabilities = project.capabilities

    WITH p, project
    MATCH (org:AzureDevOpsOrganization{id: $OrganizationName})
    MERGE (org)-[r:HAS_PROJECT]->(p)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UPDATE_TAG
    """
    neo4j_session.run(
        query,
        ProjectData=project_data,
        OrganizationName=organization_name,
        UPDATE_TAG=common_job_parameters["UPDATE_TAG"],
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job(
        "azure_devops_projects_cleanup.json", neo4j_session, common_job_parameters
    )


@timeit
def sync(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict[str, Any],
    access_token: str,
    azure_devops_url: str,
    organization_name: str,
) -> None:
    """
    Syncs the projects for the given Azure DevOps organization.
    """
    logger.info(f"Syncing projects for organization '{organization_name}'")
    projects = get_projects(azure_devops_url, organization_name, access_token)
    if projects:
        load_projects(neo4j_session, projects, organization_name, common_job_parameters)
        cleanup(neo4j_session, common_job_parameters)
