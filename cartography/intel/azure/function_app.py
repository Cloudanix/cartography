import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict
from typing import List
from typing import Optional

import neo4j
from azure.core.exceptions import HttpResponseError
from azure.mgmt.web import WebSiteManagementClient
from msrest.exceptions import DeserializationError

from .util.console_link import safe_console_link
from .util.credentials import Credentials
from .util.sdk_models import as_legacy_dict
from cartography.util import get_azure_resource_group_name
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)

# Access restriction sources that admit the whole internet ('Internet' is the service tag form).
# Azure Front Door is always internet-facing, so a site that admits it is reachable through it.
OPEN_ACCESS_RESTRICTION_SOURCES = {'any', '0.0.0.0/0', '::/0', 'internet', 'azurefrontdoor.backend'}
# Parallel per-site config reads; same order as the SQL server fetch pool.
SITE_CONFIG_WORKERS = 5


def load_function_apps(
    session: neo4j.Session, subscription_id: str,
    data_list: List[Dict], update_tag: int,
) -> None:
    session.execute_write(
        _load_function_apps_tx, subscription_id,
        data_list, update_tag,
    )


def load_function_apps_configurations(
    session: neo4j.Session,
    data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(
        _load_function_apps_configurations_tx, data_list,
        update_tag,
    )


def load_function_apps_functions(
    session: neo4j.Session, data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(
        _load_function_apps_functions_tx, data_list,
        update_tag,
    )


def load_function_apps_deployments(
    session: neo4j.Session,
    data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(
        _load_function_apps_deployments_tx, data_list,
        update_tag,
    )


def load_function_apps_backups(
    session: neo4j.Session, data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(
        _load_function_apps_backups_tx, data_list,
        update_tag,
    )


def load_function_apps_processes(
    session: neo4j.Session, data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(
        _load_function_apps_processes_tx, data_list,
        update_tag,
    )


def load_function_apps_snapshots(
    session: neo4j.Session, data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(
        _load_function_apps_snapshots_tx, data_list,
        update_tag,
    )


def load_function_apps_webjobs(
    session: neo4j.Session, data_list: List[Dict],
    update_tag: int,
) -> None:
    session.execute_write(
        _load_function_apps_webjobs_tx, data_list,
        update_tag,
    )


@timeit
def get_client(
    credentials: Credentials,
    subscription_id: str,
) -> WebSiteManagementClient:
    from .util.timing import get_timing_policy
    client = WebSiteManagementClient(credentials, subscription_id, per_call_policies=[get_timing_policy()])
    return client


@timeit
def get_function_apps_list(client: WebSiteManagementClient, regions: list, common_job_parameters: Dict) -> List[Dict]:
    try:
        function_app_list = list(
            map(as_legacy_dict, client.web_apps.list()),
        )
        function_list = []
        for function in function_app_list:
            function['resource_group'] = get_azure_resource_group_name(function.get('id'))
            function['hostNamesDisabled'] = function.get('host_names_disabled')
            function['location'] = function.get('location', '').replace(" ", "").lower()
            function['consolelink'] = safe_console_link(function['id'], common_job_parameters)
            if regions is None:
                function_list.append(function)
            else:
                if function.get('location') in regions or function.get('location') == 'global':
                    function_list.append(function)

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving function apps - {e}")
        return []

    # The site list leaves siteConfig empty, so access restrictions need one read per site.
    with ThreadPoolExecutor(max_workers=SITE_CONFIG_WORKERS) as pool:
        configs = list(pool.map(lambda site: _get_site_config(client, site), function_list))
    for site, config in zip(function_list, configs):
        _set_access_restrictions(site, config)
    return function_list


def _get_site_config(client: WebSiteManagementClient, site: Dict) -> Optional[Dict]:
    """
    Read a site's web config, which holds its access restrictions.

    :return: the config as a legacy dict, or None if it could not be read.
    """
    try:
        return as_legacy_dict(client.web_apps.get_configuration(site['resource_group'], site['name']))
    except HttpResponseError as e:
        logger.warning(f"Error while retrieving access restrictions for {site.get('id')} - {e}")
        return None


def _set_access_restrictions(site: Dict, config: Optional[Dict]) -> None:
    """
    Store the network settings the exposure job reads. When the config could not be read,
    the restriction fields stay None and the job keeps the site public.
    """
    site['publicNetworkAccess'] = site.get('public_network_access') or (config or {}).get('public_network_access')
    if config is None:
        site['ipSecurityRestrictionsDefaultAction'] = None
        site['openAccessRestriction'] = None
        return
    site['ipSecurityRestrictionsDefaultAction'] = config.get('ip_security_restrictions_default_action')
    # A rule without an action is treated as Allow, so an unclear rule keeps the site public.
    site['openAccessRestriction'] = any(
        (rule.get('action') or 'Allow').lower() == 'allow' and
        (rule.get('ip_address') or '').lower() in OPEN_ACCESS_RESTRICTION_SOURCES
        for rule in config.get('ip_security_restrictions') or []
    )


def _load_function_apps_tx(
    tx: neo4j.Transaction, subscription_id: str,
    function_apps_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_function_apps = """
    UNWIND $function_apps_list AS function_app
    MERGE (f:AzureFunctionApp{id: function_app.id})
    ON CREATE SET f.firstseen = timestamp(),
    f.type = function_app.type,
    f.location = function_app.location,
    f.region = function_app.location,
    f.resourcegroup = function_app.resource_group
    SET f.consolelink = coalesce(function_app.consolelink, f.consolelink), f.lastupdated = $update_tag,
    f.name = function_app.name,
    f.hostNamesDisabled = function_app.hostNamesDisabled,
    f.publicNetworkAccess = function_app.publicNetworkAccess,
    f.ipSecurityRestrictionsDefaultAction = function_app.ipSecurityRestrictionsDefaultAction,
    f.openAccessRestriction = function_app.openAccessRestriction,
    f.container_size = function_app.container_size,
    f.default_host_name=function_app.default_host_name,
    f.last_modified_time_utc=function_app.last_modified_time_utc,
    f.state=function_app.state,
    f.repository_site_name=function_app.repository_site_name,
    f.daily_memory_time_quota=function_app.daily_memory_time_quota,
    f.availability_state=function_app.availability_state,
    f.usage_state=function_app.usage_state
    WITH f
    MATCH (owner:AzureSubscription{id: $SUBSCRIPTION_ID})
    MERGE (owner)-[r:RESOURCE]->(f)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """

    tx.run(
        ingest_function_apps,
        function_apps_list=function_apps_list,
        SUBSCRIPTION_ID=subscription_id,
        update_tag=update_tag,
    )
    for function_app in function_apps_list:
        resource_group = get_azure_resource_group_name(function_app.get('id'))
        _attach_resource_group_function_apps(tx, function_app['id'], resource_group, update_tag)


def _attach_resource_group_function_apps(tx: neo4j.Transaction, function_app_id: str, resource_group: str, update_tag: int) -> None:
    ingest_function_apps = """
    MATCH (f:AzureFunctionApp{id: $function_app_id})
    WITH f
    MATCH (rg:AzureResourceGroup{name: $resource_group})
    MERGE (f)-[r:RESOURCE_GROUP]->(rg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $update_tag
    """
    tx.run(
        ingest_function_apps,
        function_app_id=function_app_id,
        resource_group=resource_group,
        update_tag=update_tag,
    )


def cleanup_function_apps(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
) -> None:
    run_cleanup_job(
        'azure_import_function_apps_cleanup.json', neo4j_session,
        common_job_parameters,
    )


def sync_function_apps(
    neo4j_session: neo4j.Session,
    credentials: Credentials,
    subscription_id: str,
    update_tag: int,
    common_job_parameters: Dict,
    regions: list,
) -> None:
    t0 = time.perf_counter()
    client = get_client(credentials, subscription_id)
    function_apps_list = get_function_apps_list(client, regions, common_job_parameters)
    logger.info(f"function_app sub={subscription_id}: fetch done — {len(function_apps_list)} apps in {time.perf_counter() - t0:.2f}s")
    t0 = time.perf_counter()
    load_function_apps(
        neo4j_session, subscription_id, function_apps_list,
        update_tag,
    )
    cleanup_function_apps(neo4j_session, common_job_parameters)
    logger.info(f"function_app sub={subscription_id}: load done in {time.perf_counter() - t0:.2f}s")
    t0 = time.perf_counter()
    # sync_function_apps_conf(
    #     neo4j_session, function_apps_list, client,
    #     update_tag, common_job_parameters,
    # )
    sync_function_apps_functions(
        neo4j_session, function_apps_list, client,
        update_tag, common_job_parameters,
    )
    logger.info(f"function_app sub={subscription_id}: sub-resource sync done in {time.perf_counter() - t0:.2f}s")
    # sync_function_apps_deployments(
    #     neo4j_session, function_apps_list, client,
    #     update_tag, common_job_parameters,
    # )
    # sync_function_apps_processes(
    #     neo4j_session, function_apps_list, client,
    #     update_tag, common_job_parameters,
    # )
    # sync_function_apps_backups(
    #     neo4j_session, function_apps_list, client,
    #     update_tag, common_job_parameters,
    # )
    # sync_function_apps_snapshots(
    #     neo4j_session, function_apps_list, client,
    #     update_tag, common_job_parameters,
    # )
    # sync_function_apps_webjobs(
    #     neo4j_session, function_apps_list, client,
    #     update_tag, common_job_parameters,
    # )


def get_function_apps_configuration_list(
        function_apps_list: List[Dict],
        client: WebSiteManagementClient, common_job_parameters: Dict,
) -> List[Dict]:
    try:
        function_apps_conf_list: List[Dict] = []
        for function in function_apps_list:
            apps_conf_list = list(
                map(
                    as_legacy_dict,
                    client.web_apps.list_configurations(
                        function['resource_group'], function['name'],
                    ),
                ),
            )

            for conf in apps_conf_list:
                conf['resource_group'] = get_azure_resource_group_name(conf.get('id'))
                conf['function_app_id'] = conf['id'][
                    :conf['id'].
                    index("/config/web")
                ]
                conf['consolelink'] = safe_console_link(conf['id'], common_job_parameters)
                conf["location"] = function.get("location")
                conf['publicNetworkAccess'] = conf.get('public_network_access', 'Disabled')
            function_apps_conf_list.extend(apps_conf_list)
        return function_apps_conf_list

    except HttpResponseError as e:
        logger.warning(
            f"Error while retrieving function app configurations - {e}",
        )
        return []


def _load_function_apps_configurations_tx(
    tx: neo4j.Transaction,
    function_apps_conf_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_function_apps_conf = """
    UNWIND $function_apps_conf_list as function_conf
    MERGE (fc:AzureFunctionAppConfiguration{id: function_conf.id})
    ON CREATE SET fc.firstseen = timestamp(),
    fc.type = function_conf.type
    SET fc.name = function_conf.name,
    fc.lastupdated = $azure_update_tag,
    fc.resource_group_name=function_conf.resource_group,
    fc.number_of_workers=function_conf.number_of_workers,
    fc.net_framework_version=function_conf.net_framework_version,
    fc.php_version=function_conf.php_version,
    fc.location = function_conf.location,
    fc.region = function_conf.location,
    fc.consolelink = coalesce(function_conf.consolelink, fc.consolelink),
    fc.publicNetworkAccess = function_conf.publicNetworkAccess,
    fc.python_version=function_conf.python_version,
    fc.node_version=function_conf.node_version,
    fc.linux_fx_version=function_conf.linux_fx_version,
    fc.windows_fx_version=function_conf.windows_fx_version,
    fc.request_tracing_enabled=function_conf.request_tracing_enabled,
    fc.remote_debugging_enabled=function_conf.remote_debugging_enabled,
    fc.logs_directory_size_limit=function_conf.logs_directory_size_limit,
    fc.java_version=function_conf.java_version,
    fc.auto_heal_enabled=function_conf.auto_heal_enabled,
    fc.vnet_name=function_conf.vnet_name,
    fc.local_my_sql_enabled=function_conf.local_my_sql_enabled,
    fc.ftps_state=function_conf.ftps_state,
    fc.pre_warmed_instance_count=function_conf.pre_warmed_instance_count,
    fc.health_check_path=function_conf.health_check_path
    WITH fc, function_conf
    MATCH (s:AzureFunctionApp{id: function_conf.function_app_id})
    MERGE (s)-[r:CONTAIN]->(fc)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """

    tx.run(
        ingest_function_apps_conf,
        function_apps_conf_list=function_apps_conf_list,
        azure_update_tag=update_tag,
    )
    for function_apps_conf in function_apps_conf_list:
        resource_group = get_azure_resource_group_name(function_apps_conf.get('id'))
        _attach_resource_group_function_apps_conf(tx, function_apps_conf['id'], resource_group, update_tag)


def _attach_resource_group_function_apps_conf(tx: neo4j.Transaction, function_apps_conf_id: str, resource_group: str, update_tag: int) -> None:
    ingest_function_apps_conf = """
    MATCH (fc:AzureFunctionAppConfiguration{id: $function_conf_id})
    WITH fc
    MATCH (rg:AzureResourceGroup{name: $resource_group})
    MERGE (fc)-[r:RESOURCE_GROUP]->(rg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """
    tx.run(
        ingest_function_apps_conf,
        function_conf_id=function_apps_conf_id,
        resource_group=resource_group,
        azure_update_tag=update_tag,
    )


def cleanup_function_apps_conf(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
) -> None:
    run_cleanup_job(
        'azure_import_function_apps_conf_cleanup.json',
        neo4j_session, common_job_parameters,
    )


def sync_function_apps_conf(
    neo4j_session: neo4j.Session,
    function_apps_list: List[Dict],
    client: WebSiteManagementClient,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    function_app_conf_list = get_function_apps_configuration_list(
        function_apps_list, client, common_job_parameters,
    )
    load_function_apps_configurations(
        neo4j_session, function_app_conf_list,
        update_tag,
    )
    cleanup_function_apps_conf(neo4j_session, common_job_parameters)


def get_function_apps_functions_list(
        function_apps_list: List[Dict],
        client: WebSiteManagementClient,
        common_job_parameters: Dict,
) -> List[Dict]:
    function_apps_functions_list: List[Dict] = []
    for function in function_apps_list:
        functions_list = []

        try:
            functions_list = list(
                map(
                    as_legacy_dict,
                    client.web_apps.list_functions(
                        function['resource_group'],
                        function['name'],
                    ),
                ),
            )

        except HttpResponseError as e:
            logger.warning(f"Error while retrieving function_apps functions - {e}")
            functions_list = []

        for fun in functions_list:
            fun['resource_group'] = get_azure_resource_group_name(fun.get('id'))
            fun['function_app_id'] = fun['id'][
                :fun['id'].
                index("/functions")
            ]
            fun["location"] = function.get("location", "global")
            fun['consolelink'] = safe_console_link(fun['id'], common_job_parameters)

        function_apps_functions_list.extend(functions_list)

    return function_apps_functions_list


def _load_function_apps_functions_tx(
    tx: neo4j.Transaction,
    function_apps_function_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_function = """
    UNWIND $function_apps_function_list as function
    MERGE (f:AzureFunctionAppFunction{id: function.id})
    ON CREATE SET f.firstseen = timestamp(),
    f.type = function.type
    SET f.name = function.name,
    f.lastupdated = $azure_update_tag,
    f.location = function.location,
    f.region = function.location,
    f.resource_group_name=function.resource_group,
    f.href=function.href,
    f.consolelink = coalesce(function.consolelink, f.consolelink),
    f.language=function.language,
    f.is_disabled=function.is_disabled
    WITH f, function
    MATCH (s:AzureFunctionApp{id: function.function_app_id})
    MERGE (s)-[r:CONTAIN]->(f)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """

    tx.run(
        ingest_function,
        function_apps_function_list=function_apps_function_list,
        azure_update_tag=update_tag,
    )
    for function_apps_function in function_apps_function_list:
        resource_group = get_azure_resource_group_name(function_apps_function.get('id'))
        _attach_resource_group_unction_apps_function(tx, function_apps_function['id'], resource_group, update_tag)


def _attach_resource_group_unction_apps_function(tx: neo4j.Transaction, function_apps_function_id: str, resource_group: str, update_tag: int) -> None:
    ingest_function = """
    MATCH (f:AzureFunctionAppFunction{id: $function_id})
    WITH f
    MATCH (rg:AzureResourceGroup{name: $resource_group})
    MERGE (f)-[r:RESOURCE_GROUP]->(rg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """
    tx.run(
        ingest_function,
        function_id=function_apps_function_id,
        resource_group=resource_group,
        azure_update_tag=update_tag,
    )


def cleanup_function_apps_functions(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
) -> None:
    run_cleanup_job(
        'azure_import_function_apps_function_cleanup.json',
        neo4j_session, common_job_parameters,
    )


def sync_function_apps_functions(
    neo4j_session: neo4j.Session,
    function_apps_list: List[Dict],
    client: WebSiteManagementClient,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    function_apps_function_list = get_function_apps_functions_list(
        function_apps_list, client, common_job_parameters,
    )
    load_function_apps_functions(
        neo4j_session, function_apps_function_list,
        update_tag,
    )
    cleanup_function_apps_functions(neo4j_session, common_job_parameters)


def get_function_apps_deployments_list(
        function: Dict,
        client: WebSiteManagementClient,
) -> List[Dict]:
    try:
        deployments_list = list(
            map(
                as_legacy_dict,
                client.web_apps.list_deployments(
                    function['resource_group'],
                    function['name'],
                ),
            ),
        )
        return deployments_list

    except HttpResponseError as e:
        logger.warning(
            f"Error while retrieving function apps deployments - {e}",
        )
        return []


def transform_deployments(deployments_list: List[Dict], function: Dict, common_job_parameters: Dict) -> List[Dict]:
    function_apps_deployments_list: List[Dict] = []
    for deployment in deployments_list:
        deployment['consolelink'] = safe_console_link(deployment['id'], common_job_parameters)
        deployment['resource_group'] = get_azure_resource_group_name(deployment.get('id'))
        deployment['function_app_id'] = deployment[
            'id'
        ][:deployment['id'].index("/deployments")]
        deployment["location"] = function.get("location", "global")
    function_apps_deployments_list.extend(deployments_list)

    return function_apps_deployments_list


def _load_function_apps_deployments_tx(
    tx: neo4j.Transaction,
    function_apps_deployments_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_function_apps_deploy = """
    UNWIND $function_apps_deployments_list as function_deploy
    MERGE (f:AzureFunctionAppDeployment{id: function_deploy.id})
    ON CREATE SET f.firstseen = timestamp(),
    f.type = function_deploy.type
    SET f.name = function_deploy.name,
    f.lastupdated = $azure_update_tag,
    f.consolelink = coalesce(function_deploy.consolelink, f.consolelink),
    f.location = function_deploy.location,
    f.region = function_deploy.location,
    f.resource_group_name=function_deploy.resource_group
    WITH f, function_deploy
    MATCH (s:AzureFunctionApp{id: function_deploy.function_app_id})
    MERGE (s)-[r:CONTAIN]->(f)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """

    tx.run(
        ingest_function_apps_deploy,
        function_apps_deployments_list=function_apps_deployments_list,
        azure_update_tag=update_tag,
    )
    for function_apps_deployment in function_apps_deployments_list:
        resource_group = get_azure_resource_group_name(function_apps_deployment.get('id'))
        _attach_resource_group_function_apps_deployments(tx, function_apps_deployment['id'], resource_group, update_tag)


def _attach_resource_group_function_apps_deployments(tx: neo4j.Transaction, function_apps_deployment_id: str, resource_group: str, update_tag: int) -> None:
    ingest_function_apps_deploy = """
    MATCH (f:AzureFunctionAppDeployment{id: $function_deploy_id})
    WITH f
    MATCH (rg:AzureResourceGroup{name: $resource_group})
    MERGE (f)-[r:RESOURCE_GROUP]->(rg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """
    tx.run(
        ingest_function_apps_deploy,
        function_deploy_id=function_apps_deployment_id,
        resource_group=resource_group,
        azure_update_tag=update_tag,
    )


def cleanup_function_apps_deployments(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
) -> None:
    run_cleanup_job(
        'azure_import_function_apps_deployments_cleanup.json',
        neo4j_session, common_job_parameters,
    )


def sync_function_apps_deployments(
    neo4j_session: neo4j.Session,
    function_apps_list: List[Dict],
    client: WebSiteManagementClient,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    for function in function_apps_list:
        deployments_list = get_function_apps_deployments_list(
            function, client,
        )
        function_apps_deployments_list = transform_deployments(deployments_list, function, common_job_parameters)
        load_function_apps_deployments(
            neo4j_session,
            function_apps_deployments_list, update_tag,
        )
    cleanup_function_apps_deployments(neo4j_session, common_job_parameters)


def get_function_apps_backups_list(
        function: Dict,
        client: WebSiteManagementClient,
) -> List[Dict]:
    try:
        backups_list = list(
            map(
                as_legacy_dict,
                client.web_apps.list_backups(
                    function['resource_group'],
                    function['name'],
                ),
            ),
        )
        return backups_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving function apps backups - {e}")
        return []


def transform_backups(backups_list: List[Dict], function: Dict, common_job_parameters: Dict) -> List[Dict]:
    function_apps_backups_list: List[Dict] = []
    for backup in backups_list:
        backup['consolelink'] = safe_console_link(backup['id'], common_job_parameters)
        backup['resource_group'] = get_azure_resource_group_name(backup.get('id'))
        backup['function_app_id'] = backup['id'][
            :backup['id'].
            index("/backups")
        ]
        backup["location"] = function.get("location", "global")
    function_apps_backups_list.extend(backups_list)

    return function_apps_backups_list


def _load_function_apps_backups_tx(
    tx: neo4j.Transaction,
    function_apps_backups_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_function_apps_backup = """
    UNWIND $function_apps_backups_list as function_backup
    MERGE (f:AzureFunctionAppBackup{id: function_backup.id})
    ON CREATE SET f.firstseen = timestamp(),
    f.location = function_backup.location,
    f.region = function_backup.location,
    f.type = function_backup.type
    SET f.name = function_backup.name,
    f.consolelink = coalesce(function_backup.consolelink, f.consolelink),
    f.lastupdated = $azure_update_tag,
    f.resource_group_name=function_backup.resource_group
    WITH f, function_backup
    MATCH (s:AzureFunctionApp{id: function_backup.function_app_id})
    MERGE (s)-[r:CONTAIN]->(f)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """

    tx.run(
        ingest_function_apps_backup,
        function_apps_backups_list=function_apps_backups_list,
        azure_update_tag=update_tag,
    )
    for function_apps_backup in function_apps_backups_list:
        resource_group = get_azure_resource_group_name(function_apps_backup.get('id'))
        _attach_resource_group_function_apps_backups(tx, function_apps_backup['id'], resource_group, update_tag)


def _attach_resource_group_function_apps_backups(tx: neo4j.Transaction, function_apps_backup_id: str, resource_group: str, update_tag: int) -> None:
    ingest_function_apps_backup = """
    MATCH (f:AzureFunctionAppBackup{id: $function_backup_id})
    WITH f
    MATCH (rg:AzureResourceGroup{name: $resource_group})
    MERGE (f)-[r:RESOURCE_GROUP]->(rg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """
    tx.run(
        ingest_function_apps_backup,
        function_backup_id=function_apps_backup_id,
        resource_group=resource_group,
        azure_update_tag=update_tag,
    )


def cleanup_function_apps_backups(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
) -> None:
    run_cleanup_job(
        'azure_import_function_apps_backups_cleanup.json',
        neo4j_session, common_job_parameters,
    )


def sync_function_apps_backups(
    neo4j_session: neo4j.Session,
    function_apps_list: List[Dict],
    client: WebSiteManagementClient,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    for function in function_apps_list:
        backups_list = get_function_apps_backups_list(
            function, client,
        )
        function_apps_backups_list = transform_backups(backups_list, function, common_job_parameters)
        load_function_apps_backups(
            neo4j_session, function_apps_backups_list,
            update_tag,
        )
    cleanup_function_apps_backups(neo4j_session, common_job_parameters)


def get_function_apps_processes_list(
        function: Dict,
        client: WebSiteManagementClient,
) -> List[Dict]:
    try:
        items = client.web_apps.list_processes(
            function['resource_group'],
            function['name'],
        )

        processes_list = list(
            map(
                as_legacy_dict,
                items,
            ),
        )
        return processes_list

    except DeserializationError as e:
        logger.warning(f"Error while retrieving function apps processes - {e}")
        return []


def transform_processes(processes_list: List[Dict], function: Dict, common_job_parameters: Dict) -> List[Dict]:
    function_apps_processes_list: List[Dict] = []
    for process in processes_list:
        process['consolelink'] = safe_console_link(process['id'], common_job_parameters)
        process['resource_group'] = get_azure_resource_group_name(process.get('id'))
        process['function_app_id'] = process['id'][
            :process['id'].
            index("/processes")
        ]
        process["location"] = function.get("location", "global")
    function_apps_processes_list.extend(processes_list)

    return function_apps_processes_list


def _load_function_apps_processes_tx(
    tx: neo4j.Transaction,
    function_apps_processes_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_function_apps_process = """
    UNWIND $function_apps_processes_list as function_process
    MERGE (f:AzureFunctionAppProcess{id: function_process.id})
    ON CREATE SET f.firstseen = timestamp(),
    f.location = function_process.location,
    f.region = function_process.location,
    f.type = function_process.type
    SET f.name = function_process.name,
    f.consolelink = coalesce(function_process.consolelink, f.consolelink),
    f.lastupdated = $azure_update_tag,
    f.resource_group_name=function_process.resource_group
    WITH f, function_process
    MATCH (s:AzureFunctionApp{id: function_process.function_app_id})
    MERGE (s)-[r:CONTAIN]->(f)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """

    tx.run(
        ingest_function_apps_process,
        function_apps_processes_list=function_apps_processes_list,
        azure_update_tag=update_tag,
    )
    for function_apps_process in function_apps_processes_list:
        resource_group = get_azure_resource_group_name(function_apps_process.get('id'))
        _attach_resource_group_function_apps_processes(tx, function_apps_process['id'], resource_group, update_tag)


def _attach_resource_group_function_apps_processes(tx: neo4j.Transaction, function_apps_process_id: str, resource_group: str, update_tag: int) -> None:
    ingest_function_apps_process = """
    MATCH (f:AzureFunctionAppProcess{id: $function_process_id})
    WITH f
    MATCH (rg:AzureResourceGroup{name: $resource_group})
    MERGE (f)-[r:RESOURCE_GROUP]->(rg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """
    tx.run(
        ingest_function_apps_process,
        function_process_id=function_apps_process_id,
        resource_group=resource_group,
        azure_update_tag=update_tag,
    )


def cleanup_function_apps_processes(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
) -> None:
    run_cleanup_job(
        'azure_import_function_apps_processes_cleanup.json',
        neo4j_session, common_job_parameters,
    )


def sync_function_apps_processes(
    neo4j_session: neo4j.Session,
    function_apps_list: List[Dict],
    client: WebSiteManagementClient,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    for function in function_apps_list:
        processes_list = get_function_apps_processes_list(
            function, client, common_job_parameters,
        )
        function_apps_processes_list = transform_processes(processes_list, function, common_job_parameters)
        load_function_apps_processes(
            neo4j_session, function_apps_processes_list,
            update_tag,
        )
    cleanup_function_apps_processes(neo4j_session, common_job_parameters)


def get_function_apps_snapshots_list(
        function: Dict,
        client: WebSiteManagementClient,
) -> List[Dict]:
    try:
        snapshots_list = list(
            map(
                as_legacy_dict,
                client.web_apps.list_snapshots(
                    function['resource_group'],
                    function['name'],
                ),
            ),
        )

        return snapshots_list

    except HttpResponseError as e:
        logger.warning(f"Error while retrieving function apps snapshots - {e}")
        return []


def transform_snapshots(snapshots_list: List[Dict], function: Dict, common_job_parameters: Dict) -> List[Dict]:
    function_apps_snapshots_list: List[Dict] = []
    for snapshot in snapshots_list:
        snapshot['consolelink'] = safe_console_link(snapshot['id'], common_job_parameters)
        snapshot['resource_group'] = get_azure_resource_group_name(snapshot.get('id'))
        snapshot['function_app_id'] = snapshot['id'][
            :snapshot['id'].
            index("/snapshots")
        ]
        snapshot["location"] = function.get("location", "global")
    function_apps_snapshots_list.extend(snapshots_list)

    return function_apps_snapshots_list


def _load_function_apps_snapshots_tx(
    tx: neo4j.Transaction,
    function_apps_snapshots_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_function_apps_snapshot = """
    UNWIND $function_apps_snapshots_list as function_snapshot
    MERGE (f:AzureFunctionAppSnapshot{id: function_snapshot.id})
    ON CREATE SET f.firstseen = timestamp(),
    f.location = function_snapshot.location,
    f.region = function_snapshot.location,
    f.type = function_snapshot.type
    SET f.name = function_snapshot.name,
    f.consolelink = coalesce(function_snapshot.consolelink, f.consolelink),
    f.lastupdated = $azure_update_tag,
    f.resource_group_name=function_snapshot.resource_group
    WITH f, function_snapshot
    MATCH (s:AzureFunctionApp{id: function_snapshot.function_app_id})
    MERGE (s)-[r:CONTAIN]->(f)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """

    tx.run(
        ingest_function_apps_snapshot,
        function_apps_snapshots_list=function_apps_snapshots_list,
        azure_update_tag=update_tag,
    )
    for function_apps_snapshot in function_apps_snapshots_list:
        resource_group = get_azure_resource_group_name(function_apps_snapshot.get('id'))
        _attach_resource_group_function_apps_snapshot(tx, function_apps_snapshot['id'], resource_group, update_tag)


def _attach_resource_group_function_apps_snapshot(tx: neo4j.Transaction, function_apps_snapshot_id: str, resource_group: str, update_tag: int) -> None:
    ingest_function_apps_snapshot = """
    MATCH (f:AzureFunctionAppSnapshot{id: $function_snapshot_id})
    WITH f
    MATCH (rg:AzureResourceGroup{name:$resource_group})
    MERGE (f)-[r:RESOURCE_GROUP]->(rg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """
    tx.run(
        ingest_function_apps_snapshot,
        function_snapshot_id=function_apps_snapshot_id,
        resource_group=resource_group,
        azure_update_tag=update_tag,
    )


def cleanup_function_apps_snapshots(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
) -> None:
    run_cleanup_job(
        'azure_import_function_apps_snapshots_cleanup.json',
        neo4j_session, common_job_parameters,
    )


def sync_function_apps_snapshots(
    neo4j_session: neo4j.Session,
    function_apps_list: List[Dict],
    client: WebSiteManagementClient,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    for function in function_apps_list:
        snapshots_list = get_function_apps_snapshots_list(
            function, client,
        )
        function_apps_snapshots_list = transform_snapshots(snapshots_list, function, common_job_parameters)
        load_function_apps_snapshots(
            neo4j_session, function_apps_snapshots_list,
            update_tag,
        )
    cleanup_function_apps_snapshots(neo4j_session, common_job_parameters)


def get_function_apps_webjobs_list(
        function: Dict,
        client: WebSiteManagementClient,
) -> List[Dict]:
    try:
        webjobs_list = list(
            map(
                as_legacy_dict,
                client.web_apps.list_web_jobs(
                    function['resource_group'],
                    function['name'],
                ),
            ),
        )
        return webjobs_list

    except DeserializationError as e:
        logger.warning(f"Error while retrieving function apps webjobs - {e}")
        return []


def transform_webjobs(webjobs_list: List[Dict], function: Dict, common_job_parameters: Dict) -> List[Dict]:
    function_apps_webjobs_list: List[Dict] = []
    for webjob in webjobs_list:
        webjob['consolelink'] = safe_console_link(webjob['id'], common_job_parameters)
        webjob['resource_group'] = get_azure_resource_group_name(webjob.get('id'))
        webjob['function_app_id'] = webjob['id'][
            :webjob['id'].
            index("/webjobs")
        ]
        webjob["location"] = function.get("location", "global")
    function_apps_webjobs_list.extend(webjobs_list)

    return function_apps_webjobs_list


def _load_function_apps_webjobs_tx(
    tx: neo4j.Transaction,
    function_apps_webjobs_list: List[Dict],
    update_tag: int,
) -> None:
    ingest_function_apps_webjob = """
    UNWIND $function_apps_webjobs_list as function_webjob
    MERGE (f:AzureFunctionAppWebJob{id: function_webjob.id})
    ON CREATE SET f.firstseen = timestamp(),
    f.location = function_webjob.location,
    f.region = function_webjob.location,
    f.type = function_webjob.type
    SET f.name = function_webjob.name,
    f.consolelink = coalesce(function_webjob.consolelink, f.consolelink),
    f.lastupdated = $azure_update_tag,
    f.resource_group_name=function_webjob.resource_group
    WITH f, function_webjob
    MATCH (s:AzureFunctionApp{id: function_webjob.function_app_id})
    MERGE (s)-[r:CONTAIN]->(f)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """

    tx.run(
        ingest_function_apps_webjob,
        function_apps_webjobs_list=function_apps_webjobs_list,
        azure_update_tag=update_tag,
    )
    for function_apps_webjob in function_apps_webjobs_list:
        resource_group = get_azure_resource_group_name(function_apps_webjob.get('id'))
        _attach_resource_group_function_apps_webjobs(tx, function_apps_webjob['id'], resource_group, update_tag)


def _attach_resource_group_function_apps_webjobs(tx: neo4j.Transaction, function_apps_webjob_id: str, resource_group: str, update_tag: int) -> None:
    ingest_function_apps_webjob = """
    MERGE (f:AzureFunctionAppWebJob{id: $function_webjob_id})
    WITH f
    MATCH (rg:AzureResourceGroup{name: $resource_group})
    MERGE (f)-[r:RESOURCE_GROUP]->(rg)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $azure_update_tag
    """
    tx.run(
        ingest_function_apps_webjob,
        function_webjob_id=function_apps_webjob_id,
        resource_group=resource_group,
        azure_update_tag=update_tag,
    )


def cleanup_function_apps_webjobs(
    neo4j_session: neo4j.Session,
    common_job_parameters: Dict,
) -> None:
    run_cleanup_job(
        'azure_import_function_apps_webjobs_cleanup.json',
        neo4j_session, common_job_parameters,
    )


def sync_function_apps_webjobs(
    neo4j_session: neo4j.Session,
    function_apps_list: List[Dict],
    client: WebSiteManagementClient,
    update_tag: int,
    common_job_parameters: Dict,
) -> None:
    for function in function_apps_list:
        webjobs_list = get_function_apps_webjobs_list(
            function, client,
        )
        function_apps_webjobs_list = transform_webjobs(webjobs_list, function, common_job_parameters)
        load_function_apps_webjobs(
            neo4j_session, function_apps_webjobs_list,
            update_tag,
        )
    cleanup_function_apps_webjobs(neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session,
    credentials: Credentials,
    subscription_id: str,
    update_tag: int,
    common_job_parameters: Dict,
    regions: list,
) -> None:
    logger.info(
        "Syncing function apps for subscription '%s'.",
        subscription_id,
    )

    sync_function_apps(
        neo4j_session, credentials, subscription_id, update_tag,
        common_job_parameters, regions,
    )
