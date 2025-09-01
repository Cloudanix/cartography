import logging
from typing import Any
from typing import Dict
from typing import List

import neo4j
from requests import exceptions

import cartography.intel.gitlab.group
from .resources import RESOURCE_FUNCTIONS
from cartography.config import Config
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)


def concurrent_execution(
    service: str,
    service_func: Any,
    neo4j_session: neo4j.Session,
    group_name: str,
    access_token: str,
    common_job_parameters: Dict,
):
    logger.info(f"BEGIN processing for service: {service}")
    service_func(
        neo4j_session,
        common_job_parameters["GITLAB_GROUP_ID"],
        access_token,
        common_job_parameters,
        group_name,
    )
    logger.info(f"END processing for service: {service}")


def _sync_one_gitlab_group(
    neo4j_session: neo4j.Session,
    group_name: str,
    hosted_domain: str,
    access_token: str,
    common_job_parameters: Dict[str, Any],
    config: Config,
):
    logger.info(f"Syncing Gitlab Group: {common_job_parameters['GITLAB_GROUP_ID']}")

    sync_order = ["projects", "members"]

    sync_args = {
        "neo4j_session": neo4j_session,
        "common_job_parameters": common_job_parameters,
        "group_id": common_job_parameters["GITLAB_GROUP_ID"],
        "group_name": group_name,
        "access_token": access_token,
        "hosted_domain": hosted_domain,
    }

    for func_name in sync_order:
        if func_name in RESOURCE_FUNCTIONS:
            try:
                logger.info(f"Processing {func_name}")
                RESOURCE_FUNCTIONS[func_name](**sync_args)
            except Exception as e:
                logger.warning(f"error to process service {func_name} - {e}")
        else:
            logger.warning(f'Gitlab sync function "{func_name}" was specified but is not available.')

    return True


def _sync_multiple_groups(
    neo4j_session: neo4j.Session,
    hosted_domain: str,
    access_token: str,
    groups: List[Dict],
    common_job_parameters: Dict[str, Any],
    config: Config,
) -> bool:
    for group in groups:
        if common_job_parameters["GITLAB_GROUP_ID"] != group.get("name"):
            continue

        _sync_one_gitlab_group(
            neo4j_session, group.get("name"), hosted_domain, access_token, common_job_parameters, config,
        )
        run_cleanup_job("gitlab_group_cleanup.json", neo4j_session, common_job_parameters)

    return True


@timeit
def start_gitlab_ingestion(neo4j_session: neo4j.Session, config: Config) -> None:
    """
    If this module is configured, perform ingestion of gitlab  data. Otherwise warn and exit
    :param neo4j_session: Neo4J session for database interface
    :param config: A cartography.config object
    :return: None
    """
    if not config.gitlab_access_token:
        logger.info("gitlab import is not configured - skipping this module. See docs to configure.")
        return

    access_token = config.gitlab_access_token
    hosted_domain = config.gitlab_hosted_domain
    workspace_id = config.params.get("workspace", {}).get("id_string", "")
    group_id = config.params.get("workspace", {}).get("account_id", "")

    if not isinstance(group_id, str) or not group_id:
        logger.error("GitLab 'group_id' must be configured and be a non-empty string.")
        return

    common_job_parameters = {
        "WORKSPACE_ID": workspace_id,
        "GITLAB_GROUP_ID": group_id,
        "UPDATE_TAG": config.update_tag,
    }

    try:
        # groups_list =cartography.intel.gitlab.group.get_groups(access_token)
        group_info = cartography.intel.gitlab.group.get_group(
            hosted_domain,
            access_token,
            common_job_parameters["GITLAB_GROUP_ID"],
        )
        groups_list = [group_info]

        if not groups_list or not isinstance(groups_list, list) or not groups_list[0]:
            logger.error(f"No valid groups found for the id '{common_job_parameters['GITLAB_GROUP_ID']}'.")
            return

        cartography.intel.gitlab.group.sync(
            neo4j_session,
            groups_list,
            common_job_parameters,
        )

        _sync_multiple_groups(
            neo4j_session,
            hosted_domain,
            access_token,
            groups_list,
            common_job_parameters,
            config,
        )

    except exceptions.RequestException as e:
        logger.error("Could not complete request to the Gitlab API: %s", e)

    return common_job_parameters
