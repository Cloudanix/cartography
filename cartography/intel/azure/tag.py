import math
import logging
from typing import Dict
from typing import List

from concurrent.futures import ThreadPoolExecutor, as_completed

import neo4j
from neo4j import GraphDatabase
from azure.core.exceptions import HttpResponseError
from azure.mgmt.resource import ResourceManagementClient
from cloudconsolelink.clouds.azure import AzureLinker

from .util.credentials import Credentials
from cartography.util import run_cleanup_job
from cartography.util import timeit
from cartography.config import Config

logger = logging.getLogger(__name__)
azure_console_link = AzureLinker()


def load_resource_groups(session: neo4j.Session, subscription_id: str, data_list: List[Dict], update_tag: int) -> None:
    session.write_transaction(_load_resource_groups_tx, subscription_id, data_list, update_tag)


def load_tags(session: neo4j.Session, data_list: List[Dict], update_tag: int) -> None:
    iteration_size = 100
    total_items = len(data_list)
    total_iterations = math.ceil(len(data_list) / iteration_size)
    logger.info(f"total instances: {total_items}")
    logger.info(f"total iterations: {total_iterations}")

    for counter in range(0, total_iterations):
        start = iteration_size * (counter)

        if (start + iteration_size) >= total_items:
            end = total_items
            paginated_tags = data_list[start:]

        else:
            end = start + iteration_size
            paginated_tags = data_list[start:end]

        logger.info(f"Start - Iteration {counter + 1} of {total_iterations}. {start} - {end} - {len(paginated_tags)}")

        session.write_transaction(_load_tags_tx, paginated_tags, update_tag)

        logger.info(f"End - Iteration {counter + 1} of {total_iterations}. {start} - {end} - {len(paginated_tags)}")


@timeit
def get_resource_management_client(credentials: Credentials, subscription_id: str) -> ResourceManagementClient:
    client = ResourceManagementClient(credentials, subscription_id)
    return client


@timeit
def get_resource_groups_list(client: ResourceManagementClient, common_job_parameters: Dict) -> List[Dict]:
    try:
        resource_groups_list = list(map(lambda x: x.as_dict(), client.resource_groups.list()))
        for group in resource_groups_list:
            group['consolelink'] = azure_console_link.get_console_link(
                id=group['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'])

        return resource_groups_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving resource groups - {e}")
        return []


def _load_resource_groups_tx(
    tx: neo4j.Transaction, subscription_id: str, resource_groups_list: List[Dict], update_tag: int,
) -> None:
    ingest_group = """
    UNWIND {resource_groups_list} AS group
    MERGE (t:AzureResourceGroup{id: group.id})
    ON CREATE SET t.firstseen = timestamp(),
    t.type = group.type,
    t.location = group.location,
    t.consolelink = group.consolelink,
    t.region = group.location,
    t.managedBy = group.managedBy
    SET t.lastupdated = {update_tag},
    t.name = group.name
    WITH t
    MATCH (owner:AzureSubscription{id: {SUBSCRIPTION_ID}})
    MERGE (owner)-[r:RESOURCE]->(t)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    tx.run(
        ingest_group,
        resource_groups_list=resource_groups_list,
        SUBSCRIPTION_ID=subscription_id,
        update_tag=update_tag,
    )


def cleanup_resource_groups(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_resource_groups_cleanup.json', neo4j_session, common_job_parameters)


def concurrent_execution(config: Config, client: ResourceManagementClient, resource_group: Dict, update_tag: int):
    logger.info(f"BEGIN processing for resource group: {resource_group['name']}")

    neo4j_auth = (config.neo4j_user, config.neo4j_password)
    neo4j_driver = GraphDatabase.driver(
        config.neo4j_uri,
        auth=neo4j_auth,
        max_connection_lifetime=config.neo4j_max_connection_lifetime,
    )
    tags_list: List[Dict] = []
    if "tags" in resource_group.keys() and len(resource_group['tags']) != 0:
        for tagname in resource_group['tags']:
            tags_list = tags_list + [{
                'id': resource_group['id'] + "/providers/Microsoft.Resources/tags/" + tagname,
                'key': tagname, 'value': resource_group['tags']
                [tagname], 'type': 'Microsoft.Resources/tags', 'resource_id': resource_group['id'],
                'resource_group': resource_group['name'],
            }]
    for resource in client.resources.list_by_resource_group(resource_group_name=resource_group['name']):
        if neo4j_driver.session().run("MATCH (n) WHERE n.id={id} return count(*)", id=resource.id).single().value() == 1:
            if resource.tags:
                for tagname in resource.tags:
                    tags_list = tags_list + \
                        [{
                            'id': resource.id + "/providers/Microsoft.Resources/tags/" + tagname,
                            'key': tagname, 'value': resource.tags[tagname],
                            'type': 'Microsoft.Resources/tags',
                            'resource_id': resource.id, 'resource_group': resource_group['name'],
                        }]

    load_tags(neo4j_driver.session(), tags_list, update_tag)

    logger.info(f"END processing for resource group: {resource_group['name']}")


@timeit
def get_tags_list(
    config: Config, client: ResourceManagementClient, resource_groups_list: List[Dict], update_tag: int,
) -> List[Dict]:
    try:
        with ThreadPoolExecutor(max_workers=len(resource_groups_list)) as executor:
            futures = []
            for resource_group in resource_groups_list:
                futures.append(executor.submit(concurrent_execution, config, client, resource_group, update_tag))

            for future in as_completed(futures):
                logger.info(f'Result from Future: #{future.result()}')

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving tags - {e}")
        return []


def _load_tags_tx(tx: neo4j.Transaction, tags_list: List[Dict], update_tag: int) -> None:
    ingest_tag = """
    UNWIND {tags_list} AS tag
    MERGE (t:AzureTag{id: tag.id})
    ON CREATE SET t.firstseen = timestamp(),
    t.type = tag.type,
    t.region = {region},
    t.resource_group = tag.resource_group
    SET t.lastupdated = {update_tag},
    t.value = tag.value,
    t.key = tag.key
    WITH t,tag
    MATCH (l) where l.id = tag.resource_id
    MERGE (l)-[r:TAGGED]->(t)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = {update_tag}
    """

    tx.run(
        ingest_tag,
        region="global",
        tags_list=tags_list,
        update_tag=update_tag,
    )


def cleanup_tags(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_tags_cleanup.json', neo4j_session, common_job_parameters)


def sync_tags(
    neo4j_session: neo4j.Session, client: ResourceManagementClient, resource_groups_list: List[Dict], update_tag: int,
    common_job_parameters: Dict, config: Config,
) -> None:
    get_tags_list(config, client, resource_groups_list, update_tag)
    cleanup_tags(neo4j_session, common_job_parameters)


def sync_resource_groups(
    neo4j_session: neo4j.Session, credentials: Credentials, subscription_id: str, update_tag: int,
    common_job_parameters: Dict, config: Config,
) -> None:
    client = get_resource_management_client(credentials, subscription_id)
    resource_groups_list = get_resource_groups_list(client, common_job_parameters)
    load_resource_groups(neo4j_session, subscription_id, resource_groups_list, update_tag)
    cleanup_resource_groups(neo4j_session, common_job_parameters)
    sync_tags(neo4j_session, client, resource_groups_list, update_tag, common_job_parameters, config)


@timeit
def sync(
    neo4j_session: neo4j.Session, credentials: Credentials, subscription_id: str, update_tag: int,
    common_job_parameters: Dict, config: Config,
) -> None:
    logger.info("Syncing tags for subscription '%s'.", subscription_id)

    sync_resource_groups(neo4j_session, credentials, subscription_id, update_tag, common_job_parameters, config)
