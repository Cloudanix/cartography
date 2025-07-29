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
def get_organization(api_url: str, organization_name: str, token: str) -> Dict:
    """
    Retrieve Azure DevOps organization Info.
    """
    url = f"{api_url}/{organization_name}/_apis/accounts?api-version=7.1-preview.1"
    response = call_azure_devops_api(url, token)
    # The response is a list of accounts, we need to find the one with the matching name
    if response and response.get("value"):
        for account in response["value"]:
            if account.get("accountName").lower() == organization_name.lower():
                return account
    return {}


@timeit
def load_organization(
    neo4j_session: neo4j.Session, org_data: Dict,
    common_job_parameters: Dict[str, Any],
) -> None:
    query = """
    MERGE (org:AzureDevOpsOrganization{id: $OrgId})
    ON CREATE SET org.firstseen = timestamp()
    SET org.name = $OrgName,
        org.url = $OrgUrl,
        org.status = $OrgStatus,
        org.type = $OrgType,
        org.lastupdated = $UpdateTag
    WITH org

    match (owner:CloudanixWorkspace{id:$workspace_id})
    merge (org)<-[o:OWNER]-(owner)
    ON CREATE SET o.firstseen = timestamp()
    SET o.lastupdated = $UpdateTag;
    """
    neo4j_session.run(
        query,
        OrgId=org_data.get('accountId'),
        OrgName=org_data.get('accountName'),
        OrgUrl=org_data.get('accountUri'),
        OrgStatus=org_data.get('accountStatus'),
        OrgType=org_data.get('accountType'),
        UpdateTag=common_job_parameters['UPDATE_TAG'],
        workspace_id=common_job_parameters['WORKSPACE_ID'],
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_devops_organization_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
        neo4j_session: neo4j.Session,
        azure_devops_api_key: str,
        azure_devops_org: str,
        azure_devops_url: str,
        common_job_parameters: Dict[str, Any],
) -> None:
    logger.info("Syncing Azure DevOps Organization")
    org_data = get_organization(azure_devops_url, azure_devops_org, azure_devops_api_key)

    if org_data:
        load_organization(neo4j_session, org_data, common_job_parameters)
        cleanup(neo4j_session, common_job_parameters) 