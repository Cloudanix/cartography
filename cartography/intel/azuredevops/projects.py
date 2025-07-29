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
def get_projects(api_url: str, organization_name: str, access_token: str) -> List[Dict]:
    """
    Retrieve a list of projects from the given Azure DevOps organization.
    """
    url = f"{api_url}/{organization_name}/_apis/projects?api-version=7.1-preview.4"
    response = call_azure_devops_api(url, access_token)
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
    ON MATCH SET
        p.lastupdated = $UPDATE_TAG,
        p.name = project.name,
        p.url = project.url,
        p.state = project.state,
        p.revision = project.revision,
        p.visibility = project.visibility,
        p.lastupdatetime = project.lastUpdateTime

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
    run_cleanup_job('azure_devops_projects_cleanup.json', neo4j_session, common_job_parameters)


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
        run_cleanup_job(
            "azure_devops_projects_cleanup.json",
            neo4j_session,
            common_job_parameters,
        ) 