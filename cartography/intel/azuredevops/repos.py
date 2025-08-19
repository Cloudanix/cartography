import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j

from .util import call_azure_devops_api, validate_repository_data
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_repositories_for_project(
    api_url: str, organization_name: str, project_id: str, access_token: str
) -> List[Dict]:
    """
    Retrieve a list of repositories from the given Azure DevOps project.

    Args:
        api_url: Base Azure DevOps URL (e.g., https://dev.azure.com)
        organization_name: Name of the organization
        project_id: ID of the project
        access_token: Microsoft Entra ID OAuth access token

    Returns:
        List of repository dictionaries or empty list if failed
    """
    url = f"{api_url}/{organization_name}/{project_id}/_apis/git/repositories?api-version=7.1-preview.1"

    logger.debug(f"Fetching repositories for project {project_id} from: {url}")
    response = call_azure_devops_api(url, access_token)

    if not response:
        logger.warning(f"No response received for repositories in project {project_id}")
        return []

    repos = response.get("value", [])
    # Filter out invalid repositories
    valid_repos = [r for r in repos if validate_repository_data(r)]

    if len(valid_repos) != len(repos):
        logger.warning(
            f"Filtered out {len(repos) - len(valid_repos)} invalid repositories for project {project_id}"
        )

    logger.debug(
        f"Retrieved {len(valid_repos)} valid repositories for project {project_id}"
    )
    return valid_repos


@timeit
def load_repositories(
    neo4j_session: neo4j.Session,
    repo_data: List[Dict],
    project_id: str,
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Load Azure DevOps repository data into Neo4j with comprehensive properties.
    - id: Repository ID (unique identifier)
    - name: Repository name
    - url: Repository URL
    - sshUrl: SSH clone URL
    - remoteUrl: Remote URL
    - state: Repository state
    - size: Repository size in bytes
    - defaultBranch: Default branch name
    - isDisabled: Whether repository is disabled
    - webUrl: Web interface URL
    - project: Associated project information
    """
    query = """
    UNWIND $RepoData as repo

    MERGE (r:AzureDevOpsRepo{id: repo.id})
    ON CREATE SET r.firstseen = timestamp()
    SET r.name = repo.name,
        r.url = repo.url,
        r.sshurl = repo.sshUrl,
        r.remoteurl = repo.remoteUrl,
        r.state = repo.state,
        r.size = repo.size,
        r.defaultbranch = repo.defaultBranch,
        r.isdisabled = repo.isDisabled,
        r.weburl = repo.webUrl,
        r.project = repo.project,
        r.lastupdated = $UpdateTag
    WITH r

    MATCH (p:AzureDevOpsProject{id: $ProjectId})
    MERGE (p)-[rel:HAS_REPO]->(r)
    ON CREATE SET rel.firstseen = timestamp()
    SET rel.lastupdated = $UpdateTag
    """
    neo4j_session.run(
        query,
        RepoData=repo_data,
        ProjectId=project_id,
        UpdateTag=common_job_parameters["UPDATE_TAG"],
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job(
        "azure_devops_repos_cleanup.json", neo4j_session, common_job_parameters
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
    Syncs the repositories for the given Azure DevOps organization.
    This function will iterate over all projects to get their repos.
    """
    logger.info(f"Syncing repositories for organization '{organization_name}'")
    from .projects import get_projects

    projects = get_projects(azure_devops_url, organization_name, access_token)

    for project in projects:
        project_id = project["id"]
        logger.info(f"Syncing repositories for project '{project['name']}'")
        repos = get_repositories_for_project(
            azure_devops_url, organization_name, project_id, access_token
        )
        if repos:
            load_repositories(neo4j_session, repos, project_id, common_job_parameters)

    cleanup(neo4j_session, common_job_parameters)
