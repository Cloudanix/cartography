import logging
import time
from typing import Dict
from typing import List

import neo4j
from azure.core.exceptions import HttpResponseError
from azure.mgmt.search import SearchManagementClient
from cloudconsolelink.clouds.azure import AzureLinker

from .util.credentials import Credentials
from cartography.util import get_azure_resource_group_name
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
azure_console_link = AzureLinker()


@timeit
def get_client(credentials: Credentials, subscription_id: str) -> SearchManagementClient:
    from .util.timing import get_timing_policy
    client = SearchManagementClient(
        credentials, subscription_id, per_call_policies=[get_timing_policy()],
    )
    return client


@timeit
def get_search_services_list(client: SearchManagementClient) -> List[Dict]:
    try:
        services = []
        for service in client.services.list_by_subscription():
            try:
                services.append(service.as_dict())
            except (KeyError, AttributeError) as e:
                logger.warning("Skipping AI Search service due to serialization error: %s", e)
        return services
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving AI Search services - {e}")
        return []


@timeit
def transform_search_services(services: List[Dict], regions: List, common_job_parameters: Dict) -> List[Dict]:
    data: List[Dict] = []
    for service in services:
        service['resource_group'] = get_azure_resource_group_name(service.get('id'))
        service['sku_name'] = (service.get('sku', {}) or {}).get('name')
        service['status'] = service.get('status')
        service['public_network_access'] = service.get('public_network_access')
        service['replica_count'] = service.get('replica_count')
        service['partition_count'] = service.get('partition_count')
        service['principal_id'] = (service.get('identity', {}) or {}).get('principal_id')
        try:
            service['consolelink'] = azure_console_link.get_console_link(
                id=service['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
        except (ValueError, KeyError) as e:
            logger.warning("Could not generate console link for AI Search service: %s", e)
            service['consolelink'] = ''
        if regions is None or service.get('location') in regions or service.get('location') == 'global':
            data.append(service)
    return data


@timeit
def load_search_services(
    neo4j_session: neo4j.Session, subscription_id: str, services: List[Dict], update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_search_services_tx, subscription_id, services, update_tag)


@timeit
def _load_search_services_tx(
    tx: neo4j.Transaction, subscription_id: str, services: List[Dict], update_tag: int,
) -> None:
    ingest_services = """
    UNWIND $services AS svc
    MERGE (i:AzureSearchService{id: svc.id})
    ON CREATE SET i.firstseen = timestamp()
    SET i.name = svc.name,
    i.type = svc.type,
    i.location = svc.location,
    i.region = svc.location,
    i.sku = svc.sku_name,
    i.status = svc.status,
    i.public_network_access = svc.public_network_access,
    i.replica_count = svc.replica_count,
    i.partition_count = svc.partition_count,
    i.principal_id = svc.principal_id,
    i.resourcegroup = svc.resource_group,
    i.consolelink = svc.consolelink,
    i.lastupdated = $update_tag
    WITH i
    MATCH (owner:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """
    tx.run(
        ingest_services,
        services=services,
        SUBSCRIPTION_ID=subscription_id,
        update_tag=update_tag,
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_aisearch_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, credentials: Credentials, subscription_id: str, update_tag: int,
    common_job_parameters: Dict, region: list,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing AI Search for subscription '%s'.", subscription_id)

    client = get_client(credentials.arm_credentials, subscription_id)

    services = get_search_services_list(client)
    services = transform_search_services(services, region, common_job_parameters)
    logger.info(f"Total AI Search services: {len(services)}")
    load_search_services(neo4j_session, subscription_id, services, update_tag)

    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process AI Search: {toc - tic:0.4f} seconds")
