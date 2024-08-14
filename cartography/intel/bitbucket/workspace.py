import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j
import requests
from clouduniqueid.clouds.bitbucket import BitbucketUniqueId
from requests.exceptions import RequestException

from cartography.util import make_requests_url
from cartography.util import run_cleanup_job
from cartography.util import timeit
logger = logging.getLogger(__name__)

bitbucket_linker = BitbucketUniqueId()


@timeit
def get_workspaces(access_token: str):
    url = f"https://api.bitbucket.org/2.0/workspaces?pagelen=100"

    response = make_requests_url(url, access_token)
    workspaces = response.get('values', [])

    while 'next' in response:
        response = make_requests_url(response.get('next'), access_token)
        workspaces.extend(response.get('values', []))

    return workspaces


def transform_workspaces(workspaces: List[Dict]) -> List[Dict]:
    for workspace in workspaces:
        workspace['uuid'] = workspace['uuid'].replace('{', '').replace('}', '')

        data = {
            "workspace": workspace["name"],
        }
        workspace['id'] = bitbucket_linker.get_unique_id(service="bitbucket", data=data, resourceType="workspace")
    return workspaces


def load_workspace_data(session: neo4j.Session, workspace_data: List[Dict], common_job_parameters: Dict) -> None:
    session.write_transaction(_load_workspace_data, workspace_data, common_job_parameters)


def _load_workspace_data(tx: neo4j.Transaction, workspace_data: List[Dict], common_job_parameters: Dict):
    ingest_workspace = """
    MERGE (work:BitbucketWorkspace{id: $id})
    ON CREATE SET
        work.firstseen = timestamp(),
        work.created_on = $created_on

    SET
        work.slug = $slug,
        work.type = $type,
        work.name= $name,
        work.uuid = $uuid,
        work.is_private = $is_private,
        work.lastupdated = $UpdateTag

    WITH work

    MATCH (owner:CloudanixWorkspace{id:$workspace_id})
    MERGE (work)<-[o:OWNER]-(owner)
    ON CREATE SET
        o.firstseen = timestamp()
    SET
        o.lastupdated = $UpdateTag

    """
    for workspace in workspace_data:
        tx.run(
            ingest_workspace,

            name=workspace.get("name"),
            id=workspace.get("id"),
            created_on=workspace.get('created_on'),
            slug=workspace.get('slug'),
            type=workspace.get('type'),
            uuid=workspace.get('uuid'),
            is_private=workspace.get('is_private'),
            UpdateTag=common_job_parameters['UPDATE_TAG'],
            workspace_id=common_job_parameters['WORKSPACE_ID'],
        )


def sync(
        neo4j_session: neo4j.Session,
        workspaces: List[Dict],
        common_job_parameters: Dict[str, Any],

) -> None:
    """
    Performs the sequential tasks to collect, transform, and sync bitbucket data
    :param neo4j_session: Neo4J session for database interface
    :param common_job_parameters: Common job parameters containing UPDATE_TAG
    :return: Nothing
    """
    logger.info("Syncing Bitbucket All workspaces")

    workspaces = transform_workspaces(workspaces)
    load_workspace_data(neo4j_session, workspaces, common_job_parameters)
