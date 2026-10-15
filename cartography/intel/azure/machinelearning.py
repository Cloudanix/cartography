import logging
import time
from typing import Dict
from typing import List

import neo4j
from azure.core.exceptions import HttpResponseError
from azure.mgmt.machinelearningservices import AzureMachineLearningWorkspaces
from cloudconsolelink.clouds.azure import AzureLinker

from .util.credentials import Credentials
from cartography.util import get_azure_resource_group_name
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
azure_console_link = AzureLinker()


@timeit
def get_client(credentials: Credentials, subscription_id: str) -> AzureMachineLearningWorkspaces:
    from .util.timing import get_timing_policy
    client = AzureMachineLearningWorkspaces(
        credentials, subscription_id, per_call_policies=[get_timing_policy()],
    )
    return client


@timeit
def get_workspaces_list(client: AzureMachineLearningWorkspaces) -> List[Dict]:
    try:
        workspaces = []
        for workspace in client.workspaces.list_by_subscription():
            try:
                workspaces.append(workspace.as_dict())
            except (KeyError, AttributeError) as e:
                logger.warning("Skipping ML workspace due to serialization error: %s", e)
        return workspaces
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving ML workspaces - {e}")
        return []


@timeit
def transform_workspaces(workspaces: List[Dict], regions: List, common_job_parameters: Dict) -> List[Dict]:
    data: List[Dict] = []
    for ws in workspaces:
        ws['resource_group'] = get_azure_resource_group_name(ws.get('id'))
        props = ws.get('properties', {}) or {}
        ws['friendly_name'] = props.get('friendly_name')
        ws['public_network_access'] = props.get('public_network_access')
        ws['key_vault'] = props.get('key_vault')
        ws['storage_account'] = props.get('storage_account')
        ws['container_registry'] = props.get('container_registry')
        ws['application_insights'] = props.get('application_insights')
        ws['principal_id'] = (ws.get('identity', {}) or {}).get('principal_id')
        # kind distinguishes Default workspaces from AI Foundry Hub / Project.
        ws['kind'] = ws.get('kind')
        try:
            ws['consolelink'] = azure_console_link.get_console_link(
                id=ws['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
        except (ValueError, KeyError) as e:
            logger.warning("Could not generate console link for ML workspace: %s", e)
            ws['consolelink'] = ''
        if regions is None or ws.get('location') in regions or ws.get('location') == 'global':
            data.append(ws)
    return data


@timeit
def load_workspaces(
    neo4j_session: neo4j.Session, subscription_id: str, workspaces: List[Dict], update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_workspaces_tx, subscription_id, workspaces, update_tag)


@timeit
def _load_workspaces_tx(
    tx: neo4j.Transaction, subscription_id: str, workspaces: List[Dict], update_tag: int,
) -> None:
    ingest_workspaces = """
    UNWIND $workspaces AS ws
    MERGE (i:AzureMLWorkspace{id: ws.id})
    ON CREATE SET i.firstseen = timestamp()
    SET i.name = ws.name,
    i.type = ws.type,
    i.kind = ws.kind,
    i.location = ws.location,
    i.region = ws.location,
    i.friendly_name = ws.friendly_name,
    i.public_network_access = ws.public_network_access,
    i.principal_id = ws.principal_id,
    i.resourcegroup = ws.resource_group,
    i.consolelink = ws.consolelink,
    i.lastupdated = $update_tag
    WITH i, ws
    MATCH (owner:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    FOREACH (_ IN CASE WHEN ws.key_vault IS NULL THEN [] ELSE [1] END |
        MERGE (kv:AzureKeyVault{id: ws.key_vault})
        ON CREATE SET kv.firstseen = timestamp()
        SET kv.lastupdated = $update_tag
        MERGE (i)-[uk:USES_KEY_VAULT]->(kv)
        ON CREATE SET uk.firstseen = timestamp()
        SET uk.lastupdated = $update_tag
    )
    FOREACH (_ IN CASE WHEN ws.storage_account IS NULL THEN [] ELSE [1] END |
        MERGE (sa:AzureStorageAccount{id: ws.storage_account})
        ON CREATE SET sa.firstseen = timestamp()
        SET sa.lastupdated = $update_tag
        MERGE (i)-[us:USES_STORAGE]->(sa)
        ON CREATE SET us.firstseen = timestamp()
        SET us.lastupdated = $update_tag
    )
    """
    tx.run(
        ingest_workspaces,
        workspaces=workspaces,
        SUBSCRIPTION_ID=subscription_id,
        update_tag=update_tag,
    )


@timeit
def get_models_list(client: AzureMachineLearningWorkspaces, workspace: Dict) -> List[Dict]:
    try:
        models = []
        for model in client.model_containers.list(
            resource_group_name=workspace['resource_group'], workspace_name=workspace['name'],
        ):
            try:
                models.append(model.as_dict())
            except (KeyError, AttributeError) as e:
                logger.warning("Skipping ML model due to serialization error: %s", e)
        return models
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving ML models - {e}")
        return []


@timeit
def transform_models(models: List[Dict], workspace: Dict, common_job_parameters: Dict) -> List[Dict]:
    data: List[Dict] = []
    for model in models:
        model['workspace_id'] = workspace.get('id')
        model['resource_group'] = workspace.get('resource_group')
        props = model.get('properties', {}) or {}
        model['latest_version'] = props.get('latest_version')
        try:
            model['consolelink'] = azure_console_link.get_console_link(
                id=model['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
        except (ValueError, KeyError) as e:
            logger.warning("Could not generate console link for ML model: %s", e)
            model['consolelink'] = ''
        data.append(model)
    return data


@timeit
def load_models(
    neo4j_session: neo4j.Session, subscription_id: str, models: List[Dict], update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_models_tx, subscription_id, models, update_tag)


@timeit
def _load_models_tx(
    tx: neo4j.Transaction, subscription_id: str, models: List[Dict], update_tag: int,
) -> None:
    ingest_models = """
    UNWIND $models AS model
    MERGE (i:AzureMLModel{id: model.id})
    ON CREATE SET i.firstseen = timestamp()
    SET i.name = model.name,
    i.type = model.type,
    i.latest_version = model.latest_version,
    i.resourcegroup = model.resource_group,
    i.consolelink = model.consolelink,
    i.lastupdated = $update_tag
    WITH i, model
    MATCH (owner:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH i, model
    MATCH (ws:AzureMLWorkspace{id: model.workspace_id})
    MERGE (ws)-[c:CONTAINS]->(i)
    ON CREATE SET c.firstseen = timestamp()
    SET c.lastupdated = $update_tag
    """
    tx.run(
        ingest_models,
        models=models,
        SUBSCRIPTION_ID=subscription_id,
        update_tag=update_tag,
    )


@timeit
def get_online_endpoints_list(client: AzureMachineLearningWorkspaces, workspace: Dict) -> List[Dict]:
    try:
        endpoints = []
        for endpoint in client.online_endpoints.list(
            resource_group_name=workspace['resource_group'], workspace_name=workspace['name'],
        ):
            try:
                endpoints.append(endpoint.as_dict())
            except (KeyError, AttributeError) as e:
                logger.warning("Skipping ML online endpoint due to serialization error: %s", e)
        return endpoints
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving ML online endpoints - {e}")
        return []


@timeit
def transform_online_endpoints(endpoints: List[Dict], workspace: Dict, common_job_parameters: Dict) -> List[Dict]:
    data: List[Dict] = []
    for endpoint in endpoints:
        endpoint['workspace_id'] = workspace.get('id')
        endpoint['resource_group'] = workspace.get('resource_group')
        endpoint['workspace_name'] = workspace.get('name')
        props = endpoint.get('properties', {}) or {}
        endpoint['scoring_uri'] = props.get('scoring_uri')
        endpoint['auth_mode'] = props.get('auth_mode')
        endpoint['provisioning_state'] = props.get('provisioning_state')
        endpoint['public_network_access'] = props.get('public_network_access')
        endpoint['principal_id'] = (endpoint.get('identity', {}) or {}).get('principal_id')
        try:
            endpoint['consolelink'] = azure_console_link.get_console_link(
                id=endpoint['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
        except (ValueError, KeyError) as e:
            logger.warning("Could not generate console link for ML online endpoint: %s", e)
            endpoint['consolelink'] = ''
        data.append(endpoint)
    return data


@timeit
def load_online_endpoints(
    neo4j_session: neo4j.Session, subscription_id: str, endpoints: List[Dict], update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_online_endpoints_tx, subscription_id, endpoints, update_tag)


@timeit
def _load_online_endpoints_tx(
    tx: neo4j.Transaction, subscription_id: str, endpoints: List[Dict], update_tag: int,
) -> None:
    ingest_endpoints = """
    UNWIND $endpoints AS ep
    MERGE (i:AzureMLOnlineEndpoint{id: ep.id})
    ON CREATE SET i.firstseen = timestamp()
    SET i.name = ep.name,
    i.type = ep.type,
    i.location = ep.location,
    i.region = ep.location,
    i.scoring_uri = ep.scoring_uri,
    i.auth_mode = ep.auth_mode,
    i.provisioning_state = ep.provisioning_state,
    i.public_network_access = ep.public_network_access,
    i.principal_id = ep.principal_id,
    i.resourcegroup = ep.resource_group,
    i.consolelink = ep.consolelink,
    i.lastupdated = $update_tag
    WITH i, ep
    MATCH (owner:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH i, ep
    MATCH (ws:AzureMLWorkspace{id: ep.workspace_id})
    MERGE (ws)-[c:CONTAINS]->(i)
    ON CREATE SET c.firstseen = timestamp()
    SET c.lastupdated = $update_tag
    """
    tx.run(
        ingest_endpoints,
        endpoints=endpoints,
        SUBSCRIPTION_ID=subscription_id,
        update_tag=update_tag,
    )


@timeit
def get_online_deployments_list(
    client: AzureMachineLearningWorkspaces, workspace: Dict, endpoint_name: str,
) -> List[Dict]:
    try:
        deployments = []
        for deployment in client.online_deployments.list(
            resource_group_name=workspace['resource_group'],
            workspace_name=workspace['name'],
            endpoint_name=endpoint_name,
        ):
            try:
                deployments.append(deployment.as_dict())
            except (KeyError, AttributeError) as e:
                logger.warning("Skipping ML online deployment due to serialization error: %s", e)
        return deployments
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving ML online deployments - {e}")
        return []


@timeit
def transform_online_deployments(
    deployments: List[Dict], endpoint: Dict, common_job_parameters: Dict,
) -> List[Dict]:
    data: List[Dict] = []
    for deployment in deployments:
        deployment['endpoint_id'] = endpoint.get('id')
        deployment['resource_group'] = endpoint.get('resource_group')
        props = deployment.get('properties', {}) or {}
        deployment['model'] = props.get('model')
        deployment['instance_type'] = props.get('instance_type')
        deployment['endpoint_compute_type'] = props.get('endpoint_compute_type')
        deployment['provisioning_state'] = props.get('provisioning_state')
        try:
            deployment['consolelink'] = azure_console_link.get_console_link(
                id=deployment['id'], primary_ad_domain_name=common_job_parameters['Azure_Primary_AD_Domain_Name'],
            )
        except (ValueError, KeyError) as e:
            logger.warning("Could not generate console link for ML online deployment: %s", e)
            deployment['consolelink'] = ''
        data.append(deployment)
    return data


@timeit
def load_online_deployments(
    neo4j_session: neo4j.Session, subscription_id: str, deployments: List[Dict], update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_online_deployments_tx, subscription_id, deployments, update_tag)


@timeit
def _load_online_deployments_tx(
    tx: neo4j.Transaction, subscription_id: str, deployments: List[Dict], update_tag: int,
) -> None:
    ingest_deployments = """
    UNWIND $deployments AS dep
    MERGE (i:AzureMLOnlineDeployment{id: dep.id})
    ON CREATE SET i.firstseen = timestamp()
    SET i.name = dep.name,
    i.type = dep.type,
    i.location = dep.location,
    i.region = dep.location,
    i.model = dep.model,
    i.instance_type = dep.instance_type,
    i.endpoint_compute_type = dep.endpoint_compute_type,
    i.provisioning_state = dep.provisioning_state,
    i.resourcegroup = dep.resource_group,
    i.consolelink = dep.consolelink,
    i.lastupdated = $update_tag
    WITH i, dep
    MATCH (owner:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (owner)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    WITH i, dep
    MATCH (ep:AzureMLOnlineEndpoint{id: dep.endpoint_id})
    MERGE (ep)-[hd:HAS_DEPLOYMENT]->(i)
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
    run_cleanup_job('azure_import_machinelearning_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, credentials: Credentials, subscription_id: str, update_tag: int,
    common_job_parameters: Dict, region: list,
) -> None:
    tic = time.perf_counter()
    logger.info("Syncing Machine Learning for subscription '%s'.", subscription_id)

    client = get_client(credentials.arm_credentials, subscription_id)

    workspaces = get_workspaces_list(client)
    workspaces = transform_workspaces(workspaces, region, common_job_parameters)
    logger.info(f"Total ML workspaces: {len(workspaces)}")
    load_workspaces(neo4j_session, subscription_id, workspaces, update_tag)

    for ws in workspaces:
        # Registered models
        models = get_models_list(client, ws)
        models = transform_models(models, ws, common_job_parameters)
        load_models(neo4j_session, subscription_id, models, update_tag)

        # Online endpoints + their deployments
        endpoints = get_online_endpoints_list(client, ws)
        endpoints = transform_online_endpoints(endpoints, ws, common_job_parameters)
        load_online_endpoints(neo4j_session, subscription_id, endpoints, update_tag)

        for endpoint in endpoints:
            deployments = get_online_deployments_list(client, ws, endpoint['name'])
            deployments = transform_online_deployments(deployments, endpoint, common_job_parameters)
            load_online_deployments(neo4j_session, subscription_id, deployments, update_tag)

    cleanup(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Machine Learning: {toc - tic:0.4f} seconds")
