import logging
import time
from typing import Any
from typing import Dict
from typing import List

import neo4j

from cartography.intel.gitlab.pagination import paginate_request
from cartography.intel.gitlab.projects import load_projects_data
from cartography.util import make_requests_url
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def get_groups(access_token: str):
    """
    As per the rest api docs:https://docs.gitlab.com/ee/api/api_resources.html
    List Groups: https://docs.gitlab.com/api/groups/#list-all-groups
    Pagination: https://docs.gitlab.com/ee/api/rest/index.html#pagination
    """
    url = "https://gitlab.com/api/v4/groups?per_page=100"
    groups = paginate_request(url, access_token)

    return groups


@timeit
def get_group(access_token: str, group_id: int) -> Dict:
    """
    Fetch information about a particular group.
    Group Details: https://docs.gitlab.com/ee/api/groups/#details-of-a-group
    """
    url = f"https://gitlab.com/api/v4/groups/{group_id}"
    response = make_requests_url(url, access_token)

    return response


def load_group_data(session: neo4j.Session, group_data: List[Dict], common_job_parameters: Dict) -> None:
    session.write_transaction(_load_group_data, group_data, common_job_parameters)


def _load_group_data(tx: neo4j.Transaction, group_data: List[Dict], common_job_parameters: Dict):
    ingest_group = """
    MERGE (group:GitLabGroup{id: $id})
    ON CREATE SET
        group.firstseen = timestamp(),
        group.created_at = $created_at

    SET
        group.path = $path,
        group.id = $id,
        group.name = $name,
        group.description = $description,
        group.visibility = $visibility,
        group.lastupdated = $UpdateTag

    WITH group

    MATCH (owner:CloudanixWorkspace{id:$workspace_id})
    MERGE (group)<-[o:OWNER]-(owner)
    ON CREATE SET
        o.firstseen = timestamp()
    SET
        o.lastupdated = $UpdateTag
    """

    for group in group_data:
        tx.run(
            ingest_group,
            id=group.get("id"),
            name=group.get("name"),
            created_at=group.get("created_at"),
            path=group.get("path"),
            description=group.get("description"),
            visibility=group.get("visibility"),
            web_url=group.get("web_url"),
            avatar_url=group.get("avatar_url"),
            UpdateTag=common_job_parameters["UPDATE_TAG"],
            workspace_id=common_job_parameters["WORKSPACE_ID"],
        )


def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job("gitlab_group_cleanup.json", neo4j_session, common_job_parameters)


def sync(
    neo4j_session: neo4j.Session,
    groups: List[Dict],
    common_job_parameters: Dict[str, Any],
) -> None:
    """
    Performs the sequential tasks to collect, transform, and sync gitlab data
    :param neo4j_session: Neo4J session for database interface
    :param common_job_parameters: Common job parameters containing UPDATE_TAG
    :return: Nothing
    """

    tic = time.perf_counter()
    logger.info("Syncing Groups '%s', at %s.", groups, tic)

    load_group_data(neo4j_session, groups, common_job_parameters)
