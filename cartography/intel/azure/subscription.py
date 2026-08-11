import logging
from typing import Dict
from typing import List
from typing import Optional

import neo4j
from azure.core.exceptions import HttpResponseError
from azure.mgmt.resource import SubscriptionClient
from cloudconsolelink.clouds.azure import AzureLinker

from .util.credentials import Credentials
from cartography.client.core.tx import load_graph_data
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
azure_console_link = AzureLinker()


def get_all_azure_subscriptions(credentials: Credentials, common_job_parameters: Dict) -> List[Dict]:
    try:
        # Create the client
        client = SubscriptionClient(credentials.arm_credentials)

        # Get all the accessible subscriptions
        subs = list(client.subscriptions.list())

    except HttpResponseError as e:
        logger.error(
            f'failed to fetch subscriptions for the credentials \
            The provided credentials do not have access to any subscriptions - \
            {e}',
        )

        return []

    subscriptions = []
    for sub in subs:
        subscriptions.append({
            'id': sub.id,
            'subscriptionId': sub.subscription_id,
            'displayName': sub.display_name,
            'state': sub.state,
            'consolelink': azure_console_link.get_console_link(
                id=sub.subscription_id,
                primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            ),
        })

    return subscriptions


def get_current_azure_subscription(credentials: Credentials, subscription_id: Optional[str], common_job_parameters: Dict) -> List[Dict]:
    try:
        # Create the client
        client = SubscriptionClient(credentials.arm_credentials)

        # Get all the accessible subscriptions
        sub = client.subscriptions.get(subscription_id)

    except HttpResponseError as e:
        logger.error(
            f'failed to fetch subscription for the credentials \
            The provided credentials do not have access to this subscription: {subscription_id} - \
            {e}',
        )

        return []

    return [
        {
            'id': sub.id,
            'subscriptionId': sub.subscription_id,
            'displayName': sub.display_name,
            'state': sub.state,
            'consolelink': azure_console_link.get_console_link(
                id=sub.subscription_id,
                primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            ),
        },
    ]


def load_azure_subscriptions(
    neo4j_session: neo4j.Session, tenant_id: str, subscriptions: List[Dict], update_tag: int,
) -> None:
    query = """
    UNWIND $DictList AS item
    MERGE (at:AzureTenant{id: $TENANT_ID})
    ON CREATE SET at.firstseen = timestamp(),
    at.region = 'global'
    SET at.lastupdated = $update_tag
    WITH at, item
    MERGE (as:AzureSubscription{id: item.subscriptionId})
    ON CREATE SET as.firstseen = timestamp(), as.path = item.id,
    as.region = 'global'
    SET as.lastupdated = $update_tag, as.name = item.displayName, as.state = item.state,
    as.consolelink = item.consolelink
    WITH as, at
    MERGE (at)-[r:RESOURCE]->(as)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag;
    """
    load_graph_data(
        neo4j_session, query, subscriptions,
        TENANT_ID=tenant_id, update_tag=update_tag,
    )


def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_subscriptions_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, tenant_id: str, subscriptions: List[Dict], update_tag: int,
    common_job_parameters: Dict,
) -> None:
    load_azure_subscriptions(neo4j_session, tenant_id, subscriptions, update_tag)

    for sub in subscriptions:
        common_job_parameters['AZURE_SUBSCRIPTION_ID'] = sub['subscriptionId']
        common_job_parameters['AZURE_TENANT_ID'] = tenant_id

        cleanup(neo4j_session, common_job_parameters)

    del common_job_parameters['AZURE_SUBSCRIPTION_ID']
    del common_job_parameters['AZURE_TENANT_ID']
