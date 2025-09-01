import logging
import time
from typing import Any
from typing import Dict
from typing import List

import neo4j

from cartography.intel.gitlab.pagination import paginate_request
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_group_projects(hosted_domain: str, access_token: str, group_id: int):
    """
    As per the rest api docs:https://docs.gitlab.com/api/groups.html#list-a-groups-projects
    Pagination: https://docs.gitlab.com/api/rest/index.html#pagination
    """
    url = f"{hosted_domain}/api/v4/groups/{group_id}/projects?per_page=100"
    projects = paginate_request(url, access_token)

    return projects


def load_projects_data(
    session: neo4j.Session,
    project_data: List[Dict],
    common_job_parameters: Dict,
    group_id: int,
) -> None:
    session.write_transaction(_load_projects_data, project_data, common_job_parameters, group_id)


def _load_projects_data(
    tx: neo4j.Transaction,
    project_data: List[Dict],
    common_job_parameters: Dict,
    group_id: int,
) -> None:
    ingest_group = """
    UNWIND $projectData as project
    MERGE (pro:GitLabProject {id: project.id})
    ON CREATE SET
        pro.firstseen = timestamp(),
        pro.created_at = project.created_at

    SET
        pro.name = project.name,
        pro.archived = project.archived,
        pro.avatar_url = project.avatar_url,
        pro.creator_id = project.creator_id,
        pro.web_url = project.web_url,
        pro.path = project.path,
        pro.path_with_namespace = project.path_with_namespace,
        pro.description = project.description,
        pro.name_with_namespace = project.name_with_namespace,
        pro.visibility = project.visibility,
        pro.is_private = project.visibility == 'private',
        pro.namespace= project.namespace.path,
        pro.last_activity_at = project.last_activity_at,
        pro.default_branch = project.default_branch,
        pro.lastupdated = $UpdateTag

    WITH pro, project
    MATCH (group:GitLabGroup{id: $GroupId})
    MERGE (group)-[r:RESOURCE]->(pro)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $UpdateTag
    """

    tx.run(
        ingest_group,
        projectData=project_data,
        UpdateTag=common_job_parameters["UPDATE_TAG"],
        GroupId=group_id,
    )


def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("gitlab_group_project_cleanup.json", neo4j_session, common_job_parameters)


def sync(
    neo4j_session: neo4j.Session,
    group_id: int,
    hosted_domain: str,
    access_token: str,
    common_job_parameters: Dict[str, Any],
    group_name: str,
) -> None:
    """
    Performs the sequential tasks to collect, transform, and sync gitlab data
    :param neo4j_session: Neo4J session for database interface
    :param common_job_parameters: Common job parameters containing UPDATE_TAG
    :return: Nothing
    """
    tic = time.perf_counter()

    logger.info("Syncing Projects for Gitlab Group '%s', at %s.", group_name, tic)

    group_projects = get_group_projects(access_token, group_id)

    load_projects_data(neo4j_session, group_projects, common_job_parameters, group_id)
    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Projects for Gitlab Group '{group_name}': {toc - tic:0.4f} seconds")
