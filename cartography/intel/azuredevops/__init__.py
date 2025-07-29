import base64
import json
import logging
import os
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from typing import Dict
from typing import List

import neo4j
from neo4j import GraphDatabase
from requests import exceptions

from . import organization
from .resources import RESOURCE_FUNCTIONS
from .util import get_access_token
from cartography.config import Config
from cartography.graph.session import Session
from cartography.util import timeit

logger = logging.getLogger(__name__)


@timeit
def concurrent_execution(
    service: str, service_func: Any, config: Config, org_name: str,
    url: str, access_token: str, common_job_parameters: Dict,
):
    logger.info(f"BEGIN processing for service: {service} for organization {org_name}")
    neo4j_auth = (config.neo4j_user, config.neo4j_password)
    neo4j_driver = GraphDatabase.driver(
        config.neo4j_uri,
        auth=neo4j_auth,
        max_connection_lifetime=config.neo4j_max_connection_lifetime,
    )
    service_func(
        Session(neo4j_driver), common_job_parameters, access_token, url, org_name,
    )
    logger.info(f"END processing for service: {service} for organization {org_name}")


@timeit
def sync_organization(
    neo4j_session: neo4j.Session, config: Config, org_name: str, url: str, access_token: str, common_job_parameters: Dict,
) -> None:
    try:
        logger.info("Syncing Azure DevOps Organization: %s", org_name)
        organization.sync(
            neo4j_session,
            access_token,
            org_name,
            url,
            common_job_parameters,
        )

        requested_syncs: List[str] = list(RESOURCE_FUNCTIONS.keys())

        with ThreadPoolExecutor(max_workers=len(requested_syncs)) as executor:
            futures = []
            for func_name in requested_syncs:
                logger.info(f"Queueing {func_name} for {org_name}")
                futures.append(
                    executor.submit(
                        concurrent_execution,
                        func_name,
                        RESOURCE_FUNCTIONS[func_name],
                        config,
                        org_name,
                        url,
                        access_token,
                        common_job_parameters,
                    ),
                )

            for future in as_completed(futures):
                logger.info(f'Result from Future - Service Processing: {future.result()}')

    except exceptions.RequestException as e:
        logger.error("Could not complete request to the Azure DevOps API: %s", e)


@timeit
def start_azure_devops_ingestion(neo4j_session: neo4j.Session, config: Config) -> None:
    """
    If this module is configured, perform ingestion of Azure DevOps data. Otherwise warn and exit
    :param neo4j_session: Neo4J session for database interface
    :param config: A cartography.config object
    :return: None
    """
    if not config.azure_devops_config:
        logger.info('Azure DevOps import is not configured - skipping this module. See docs to configure.')
        return

    try:
        auth_details = json.loads(base64.b64decode(config.azure_devops_config).decode())
    except (json.JSONDecodeError, TypeError) as e:
        logger.error(f"Failed to parse Azure DevOps config: {e}", exc_info=True)
        return

    common_job_parameters = {
        "WORKSPACE_ID": config.params['workspace']['id_string'],
        "UPDATE_TAG": config.update_tag,
    }

    for account in auth_details.get('accounts', []):
        try:
            token_data = get_access_token(
                account['tenant_id'],
                account['client_id'],
                account['client_secret'],
                account['refresh_token'],
            )
            if not token_data or 'access_token' not in token_data:
                logger.error(f"Failed to retrieve Azure DevOps access token for tenant {account.get('tenant_id')}")
                continue

            access_token = token_data['access_token']
        except Exception as e:
            logger.error(
                f"Failed to retrieve Azure DevOps access token for tenant {account.get('tenant_id')}: {e}",
                exc_info=True,
            )
            continue

        for org_name in account.get('organization_names', []):
            sync_organization(
                neo4j_session, config, org_name, account['url'], access_token, common_job_parameters,
            )

    return common_job_parameters 