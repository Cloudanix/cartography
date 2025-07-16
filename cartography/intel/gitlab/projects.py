import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j

from cartography.intel.gitlab.pagination import paginate_request
from cartography.util import make_requests_url
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_projects(access_token:str,group:str):
    """
    As per the rest api docs:https://docs.gitlab.com/ee/api/groups.html#list-a-groups-projects
    Pagination: https://docs.gitlab.com/ee/api/rest/index.html#pagination
    """
    url = f"https://gitlab.com/api/v4/groups/{group}/projects?per_page=100"
    projects = paginate_request(url, access_token)

    return projects


def load_projects_data(session: neo4j.Session, project_data:List[Dict],common_job_parameters:Dict) -> None:
    session.write_transaction(_load_projects_data, project_data,  common_job_parameters)


def _load_projects_data(tx: neo4j.Transaction,project_data:List[Dict],common_job_parameters:Dict):
    ingest_group="""
    UNWIND $projectData as project
    MERGE (pro:GitLabProject {id: project.id})
    ON CREATE SET pro.firstseen = timestamp(),
    pro.created_at = project.created_at

    SET pro.description = project.description,
    pro.name = project.name,
    pro.name_with_namespace = project.name_with_namespace,
    pro.id = project.id,
    pro.visibility = project.visibility,
    pro.namespace= project.namespace.path,
    pro.last_activity_at = project.last_activity_at,
    pro.default_branch = project.default_branch,
    pro.lastupdated = $UpdateTag

    WITH pro, project
    MATCH (group:GitLabGroup{id: project.namespace.id})
    MERGE (group)-[r:RESOURCE]->(pro)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """

    tx.run(
        ingest_group,
        projectData=project_data,
        UpdateTag=common_job_parameters['UPDATE_TAG'],
    )


def cleanup(neo4j_session: neo4j.Session,  common_job_parameters: Dict) -> None:
    run_cleanup_job('gitlab_group_project_cleanup.json', neo4j_session, common_job_parameters)


def sync(
        neo4j_session: neo4j.Session,
        group_name:str,
        access_token:str,
        common_job_parameters: Dict[str, Any],
) -> None:
    """
    Performs the sequential tasks to collect, transform, and sync gitlab data
    :param neo4j_session: Neo4J session for database interface
    :param common_job_parameters: Common job parameters containing UPDATE_TAG
    :return: Nothing
    """
    logger.info("Syncing Gitlab All group Projects ")
    group_projects=get_projects(access_token,group_name)
    load_projects_data(neo4j_session,group_projects,common_job_parameters)
    cleanup(neo4j_session,common_job_parameters)
