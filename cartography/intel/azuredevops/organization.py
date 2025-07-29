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
def get_organization(api_url: str, organization_name: str, access_token: str) -> Dict:
    """
    Retrieve Azure DevOps organization Info.
    """
    url = f"{api_url}/_apis/organizations/{organization_name}?api-version=7.1-preview.1"
    response = call_azure_devops_api(url, access_token)
    return response if response else {}


@timeit
def load_organization(
    neo4j_session: neo4j.Session,
    org_data: Dict,
    common_job_parameters: Dict[str, Any],
) -> None:
    query = """
    MERGE (org:AzureDevOpsOrganization{id: $OrgName})
    ON CREATE SET org.firstseen = timestamp()
    SET org.url = $OrgUrl,
        org.status = $OrgStatus,
        org.type = $OrgType,
        org.lastupdated = $UpdateTag
    WITH org

    MATCH (owner:CloudanixWorkspace{id:$workspace_id})
    MERGE (org)<-[o:OWNER]-(owner)
    ON CREATE SET o.firstseen = timestamp()
    SET o.lastupdated = $UpdateTag;
    """
    neo4j_session.run(
        query,
        OrgName=org_data.get("name"),
        OrgUrl=org_data.get("url"),
        OrgStatus=org_data.get("status"),
        OrgType=org_data.get("type"),
        UpdateTag=common_job_parameters["UPDATE_TAG"],
        workspace_id=common_job_parameters["WORKSPACE_ID"],
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_devops_organization_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict[str, Any],
    access_token: str,
    url: str,
    org_name: str,
) -> None:
    logger.info(f"Syncing Azure DevOps Organization '{org_name}'")
    org_data = get_organization(url, org_name, access_token)
    if org_data:
        load_organization(neo4j_session, org_data, common_job_parameters)
        cleanup(neo4j_session, common_job_parameters) 