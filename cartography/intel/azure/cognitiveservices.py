import logging
import time
from typing import Dict
from typing import List

import neo4j
from azure.core.exceptions import HttpResponseError
from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from cloudconsolelink.clouds.azure import AzureLinker

from .util.credentials import Credentials
from cartography.util import get_azure_resource_group_name
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
azure_console_link = AzureLinker()


@timeit
def get_client(credentials: Credentials, subscription_id: str) -> CognitiveServicesManagementClient:
    from .util.timing import get_timing_policy
    client = CognitiveServicesManagementClient(
        credentials, subscription_id, per_call_policies=[get_timing_policy()],
    )
    return client


@timeit
def get_accounts_list(client: CognitiveServicesManagementClient) -> List[Dict]:
    try:
        accounts = []
        for account in client.accounts.list():
            try:
                accounts.append(account.as_dict())
            except (KeyError, AttributeError) as e:
                logger.warning("Skipping cognitive services account due to serialization error: %s", e)
        return accounts
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving cognitive services accounts - {e}")
        return []


@timeit
def transform_accounts(accounts: List[Dict], regions: List, common_job_parameters: Dict) -> List[Dict]:
    data: List[Dict] = []
    for account in accounts:
        account['resource_group'] = get_azure_resource_group_name(account.get('id'))
        props = account.get('properties', {}) or {}
        account['endpoint'] = props.get('endpoint')
        account['public_network_access'] = props.get('public_network_access')
        account['custom_sub_domain_name'] = props.get('custom_sub_domain_name')
        account['provisioning_state'] = props.get('provisioning_state')
        account['sku_name'] = (account.get('sku', {}) or {}).get('name')
        account['principal_id'] = (account.get('identity', {}) or {}).get('principal_id')
        # Customer-managed key encryption (CMK) is only present when configured.
        encryption = props.get('encryption', {}) or {}
        kv_props = encryption.get('key_vault_properties', {}) or {}
        account['key_source'] = encryption.get('key_source')
        account['key_vault_uri'] = kv_props.get('key_vault_arm_id') or kv_props.get('key_vault_uri')
        try:
            account['consolelink'] = azure_console_link.get_console_link(
                id=account['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
        except (ValueError, KeyError) as e:
            logger.warning("Could not generate console link for cognitive services account: %s", e)
            account['consolelink'] = ''
        if regions is None or account.get('location') in regions or account.get('location') == 'global':
            data.append(account)
    return data


@timeit
def load_accounts(
    neo4j_session: neo4j.Session, subscription_id: str, accounts: List[Dict], update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_accounts_tx, subscription_id, accounts, update_tag)


@timeit
def _load_accounts_tx(
    tx: neo4j.Transaction, subscription_id: str, accounts: List[Dict], update_tag: int,
) -> None:
    ingest_accounts = """
    UNWIND $accounts AS acc
    MERGE (i:AzureCognitiveServicesAccount{id: acc.id})
    ON CREATE SET i.firstseen = timestamp()
    SET i.name = acc.name,
    i.kind = acc.kind,
    i.type = acc.type,
    i.location = acc.location,
    i.region = acc.location,
    i.sku = acc.sku_name,
    i.endpoint = acc.endpoint,
    i.public_network_access = acc.public_network_access,
    i.custom_sub_domain_name = acc.custom_sub_domain_name,
    i.provisioning_state = acc.provisioning_state,
    i.key_source = acc.key_source,
    i.principal_id = acc.principal_id,
    i.resourcegroup = acc.resource_group,
    i.consolelink = acc.consolelink,
    i.lastupdated = $update_tag
    WITH i, acc
    MATCH (owner:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    FOREACH (_ IN CASE WHEN acc.key_vault_uri IS NULL THEN [] ELSE [1] END |
        MERGE (kv:AzureKeyVault{id: acc.key_vault_uri})
        ON CREATE SET kv.firstseen = timestamp()
        SET kv.lastupdated = $update_tag
        MERGE (i)-[enc:ENCRYPTED_BY]->(kv)
        ON CREATE SET enc.firstseen = timestamp()
        SET enc.lastupdated = $update_tag
    )
    """
    tx.run(
        ingest_accounts,
        accounts=accounts,
        SUBSCRIPTION_ID=subscription_id,
        update_tag=update_tag,
    )


@timeit
def get_deployments_list(client: CognitiveServicesManagementClient, account: Dict) -> List[Dict]:
    try:
        deployments = []
        for deployment in client.deployments.list(
            resource_group_name=account['resource_group'], account_name=account['name'],
        ):
            try:
                deployments.append(deployment.as_dict())
            except (KeyError, AttributeError) as e:
                logger.warning("Skipping cognitive services deployment due to serialization error: %s", e)
        return deployments
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving cognitive services deployments - {e}")
        return []


@timeit
def transform_deployments(deployments: List[Dict], account: Dict, common_job_parameters: Dict) -> List[Dict]:
    data: List[Dict] = []
    for deployment in deployments:
        deployment['resource_group'] = account.get('resource_group')
        deployment['account_id'] = account.get('id')
        props = deployment.get('properties', {}) or {}
        model = props.get('model', {}) or {}
        deployment['model_name'] = model.get('name')
        deployment['model_version'] = model.get('version')
        deployment['model_format'] = model.get('format')
        deployment['rai_policy_name'] = props.get('rai_policy_name')
        deployment['provisioning_state'] = props.get('provisioning_state')
        deployment['sku_name'] = (deployment.get('sku', {}) or {}).get('name')
        deployment['sku_capacity'] = (deployment.get('sku', {}) or {}).get('capacity')
        try:
            deployment['consolelink'] = azure_console_link.get_console_link(
                id=deployment['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
        except (ValueError, KeyError) as e:
            logger.warning("Could not generate console link for cognitive services deployment: %s", e)
            deployment['consolelink'] = ''
        data.append(deployment)
    return data


@timeit
def load_deployments(
    neo4j_session: neo4j.Session, subscription_id: str, deployments: List[Dict], update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_deployments_tx, subscription_id, deployments, update_tag)


@timeit
def _load_deployments_tx(
    tx: neo4j.Transaction, subscription_id: str, deployments: List[Dict], update_tag: int,
) -> None:
    ingest_deployments = """
    UNWIND $deployments AS dep
    MERGE (i:AzureCognitiveServicesDeployment{id: dep.id})
    ON CREATE SET i.firstseen = timestamp()
    SET i.name = dep.name,
    i.type = dep.type,
    i.model_name = dep.model_name,
    i.model_version = dep.model_version,
    i.model_format = dep.model_format,
    i.rai_policy_name = dep.rai_policy_name,
    i.provisioning_state = dep.provisioning_state,
    i.sku = dep.sku_name,
    i.sku_capacity = dep.sku_capacity,
    i.resourcegroup = dep.resource_group,
    i.consolelink = dep.consolelink,
    i.lastupdated = $update_tag
    WITH i, dep
    MATCH (owner:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH i, dep
    MATCH (acc:AzureCognitiveServicesAccount{id: dep.account_id})
    MERGE (acc)-[hd:HAS_DEPLOYMENT]->(i)
    ON CREATE SET hd.firstseen = timestamp()
    SET hd.lastupdated = $update_tag
    """
    tx.run(
        ingest_deployments,
        deployments=deployments,
        SUBSCRIPTION_ID=subscription_id,
        update_tag=update_tag,
    )


@timeit
def cleanup(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('azure_import_cognitiveservices_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, credentials: Credentials, subscription_id: str, update_tag: int,
    common_job_parameters: Dict, region: list,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing Cognitive Services for subscription '%s'.", subscription_id)

    client = get_client(credentials.arm_credentials, subscription_id)

    accounts = get_accounts_list(client)
    accounts = transform_accounts(accounts, region, common_job_parameters)
    logger.info(f"Total cognitive services accounts: {len(accounts)}")
    load_accounts(neo4j_session, subscription_id, accounts, update_tag)

    # Deployments are scoped per account.
    for account in accounts:
        deployments = get_deployments_list(client, account)
        deployments = transform_deployments(deployments, account, common_job_parameters)
        load_deployments(neo4j_session, subscription_id, deployments, update_tag)

    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Cognitive Services: {toc - tic:0.4f} seconds")
