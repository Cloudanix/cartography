import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j
import requests

from cartography.util import make_requests_url
from cartography.util import run_cleanup_job
from cartography.util import timeit
logger = logging.getLogger(__name__)


@timeit
def get_projects(access_token:str,workspace:str):
    url = f"https://api.bitbucket.org/2.0/workspaces/{workspace}/projects?pagelen=100"

    response = make_requests_url(url,access_token)
    projects = response.get('values', [])

    while 'next' in response:
        response = make_requests_url(response.get('next'),access_token)
        projects.extend(response.get('values', []))

    return projects

def transform_projects(workspace_projects: List[Dict]) -> List[Dict]:
    for project in workspace_projects:
        project['workspace']['uuid'] = project['workspace']['uuid'].replace('{','').replace('}','')
        project['uuid'] = project['uuid'].replace('{','').replace('}','')

    return workspace_projects

def load_projects_data(session: neo4j.Session, project_data:List[Dict],common_job_parameters:Dict) -> None:
    session.write_transaction(_load_projects_data, project_data,  common_job_parameters)


def _load_projects_data(tx: neo4j.Transaction,project_data:List[Dict],common_job_parameters:Dict):
    ingest_workspace="""
    UNWIND $projectData as project
    MERGE (pro:BitbucketProject{id: project.uuid})
    ON CREATE SET pro.firstseen = timestamp(),
    pro.created_on = project.created_on

    SET pro.description = project.description,
    pro.type = project.type,
    pro.name=project.name,
    pro.uuid = project.uuid,
    pro.is_private = project.is_private,
    pro.has_publicly_visible_repos=project.has_publicly_visible_repos,
    pro.key=project.key,
    pro.owner=project.owner.display_name,
    pro.type=project.type,
    pro.updated_on=project.updated_on,
    pro.lastupdated = $UpdateTag

    WITH pro,project
    MATCH (work:BitbucketWorkspace{id:project.workspace.uuid})
    merge (work)-[o:RESOURCE]->(pro)
    ON CREATE SET o.firstseen = timestamp()
    SET o.lastupdated = $UpdateTag
    """

    tx.run(
        ingest_workspace,
        projectData=project_data,
        UpdateTag=common_job_parameters['UPDATE_TAG'],
    )


def cleanup(neo4j_session: neo4j.Session,  common_job_parameters: Dict) -> None:
    run_cleanup_job('bitbucket_workspace_project_cleanup.json', neo4j_session, common_job_parameters)


def sync(
        neo4j_session: neo4j.Session,
        workspace_name:str,
        bitbucket_access_token:str,
        common_job_parameters: Dict[str, Any],
) -> None:
    """
    Performs the sequential tasks to collect, transform, and sync bitbucket data
    :param neo4j_session: Neo4J session for database interface
    :param common_job_parameters: Common job parameters containing UPDATE_TAG
    :return: Nothing
    """
    logger.info("Syncing Bitbucket All workspace Projects ")
    workspace_projects=get_projects(bitbucket_access_token,workspace_name)
    workspace_projects=transform_projects(workspace_projects)
    load_projects_data(neo4j_session,workspace_projects,common_job_parameters)
    cleanup(neo4j_session,common_job_parameters)