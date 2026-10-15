import logging
import time
from typing import Dict
from typing import List

import boto3
import neo4j
from cloudconsolelink.clouds.aws import AWSLinker

from cartography.intel.aws.ec2.util import get_botocore_config
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
aws_console_link = AWSLinker()


def get_boto3_client(boto3_session: boto3.session.Session, service: str, region: str):
    client = boto3_session.client(service, region_name=region, config=get_botocore_config())
    return client


@timeit
def get_qbusiness_applications_list(
    boto3_session: boto3.session.Session,
    current_aws_account_id: str,
    region: str,
) -> List[Dict]:
    applications: List[Dict] = []
    try:
        client = get_boto3_client(boto3_session, "qbusiness", region)
        paginator = client.get_paginator("list_applications")
        for page in paginator.paginate():
            applications.extend(page["applications"])

        for app in applications:
            app["region"] = region
            app["arn"] = f"arn:aws:qbusiness:{region}:{current_aws_account_id}:application/{app['applicationId']}"
            app["consolelink"] = aws_console_link.get_console_link(arn=app["arn"])
            # The list summary omits the IAM role; enrich with get_application.
            try:
                detail = client.get_application(applicationId=app["applicationId"])
                app["roleArn"] = detail.get("roleArn")
                app["identityCenterApplicationArn"] = detail.get("identityCenterApplicationArn")
            except Exception as e:
                logger.warning(
                    f"Could not get details for qbusiness application {app['applicationId']}. "
                    f"skipping enrichment. - {e}",
                )
    except Exception as e:
        logger.warning(f"Could not list qbusiness applications. skipping. - {e}")
    return applications


@timeit
def load_qbusiness_applications(
    neo4j_session: neo4j.Session,
    applications: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_qbusiness_applications_tx, applications, current_aws_account_id, aws_update_tag)


@timeit
def _load_qbusiness_applications_tx(
    tx: neo4j.Transaction,
    applications: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_applications = """
    UNWIND $applications AS app
    MERGE (i:AWSQBusinessApplication{arn:app.arn})
    ON CREATE SET i.firstseen = timestamp(),
    i.arn = app.arn,
    i.applicationid = app.applicationId
    SET i.name = app.displayName,
    i.status = app.status,
    i.identitytype = app.identityType,
    i.rolearn = app.roleArn,
    i.identitycenterapplicationarn = app.identityCenterApplicationArn,
    i.createdat = app.createdAt,
    i.updatedat = app.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = app.region,
    i.consolelink = app.consolelink
    WITH i, app
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    FOREACH (_ IN CASE WHEN app.roleArn IS NULL THEN [] ELSE [1] END |
        MERGE (p:AWSPrincipal{arn: app.roleArn})
        ON CREATE SET p.firstseen = timestamp()
        SET p.lastupdated = $aws_update_tag
        MERGE (i)-[ar:QBUSINESS_ASSUMEROLE_ALLOW]->(p)
        ON CREATE SET ar.firstseen = timestamp()
        SET ar.lastupdated = $aws_update_tag
    )
    """

    tx.run(
        ingest_applications,
        applications=applications,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_qbusiness_indices_list(
    boto3_session: boto3.session.Session,
    applications: List[Dict],
    region: str,
) -> List[Dict]:
    indices: List[Dict] = []
    client = get_boto3_client(boto3_session, "qbusiness", region)
    # list_indices is scoped to a single application.
    for app in applications:
        if app.get("region") != region:
            continue
        application_id = app["applicationId"]
        app_arn = app["arn"]
        try:
            app_indices: List[Dict] = []
            paginator = client.get_paginator("list_indices")
            for page in paginator.paginate(applicationId=application_id):
                app_indices.extend(page["indices"])

            for index in app_indices:
                index["region"] = region
                index["applicationId"] = application_id
                index["applicationArn"] = app_arn
                index["id"] = f"{application_id}/{index['indexId']}"

            indices.extend(app_indices)
        except Exception as e:
            logger.warning(
                f"Could not list qbusiness indices for application {application_id}. skipping. - {e}",
            )
    return indices


@timeit
def load_qbusiness_indices(
    neo4j_session: neo4j.Session,
    indices: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_qbusiness_indices_tx, indices, current_aws_account_id, aws_update_tag)


@timeit
def _load_qbusiness_indices_tx(
    tx: neo4j.Transaction,
    indices: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_indices = """
    UNWIND $indices AS index
    MERGE (i:AWSQBusinessIndex{id:index.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = index.id,
    i.indexid = index.indexId
    SET i.name = index.displayName,
    i.status = index.status,
    i.applicationid = index.applicationId,
    i.createdat = index.createdAt,
    i.updatedat = index.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = index.region
    WITH i, index
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, index
    MATCH (app:AWSQBusinessApplication{arn: index.applicationArn})
    MERGE (app)-[hi:HAS_INDEX]->(i)
    ON CREATE SET hi.firstseen = timestamp()
    SET hi.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_indices,
        indices=indices,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_qbusiness_data_sources_list(
    boto3_session: boto3.session.Session,
    indices: List[Dict],
    region: str,
) -> List[Dict]:
    data_sources: List[Dict] = []
    client = get_boto3_client(boto3_session, "qbusiness", region)
    # list_data_sources is scoped to a single application + index.
    for index in indices:
        if index.get("region") != region:
            continue
        application_id = index["applicationId"]
        index_id = index["indexId"]
        index_node_id = index["id"]
        try:
            index_data_sources: List[Dict] = []
            paginator = client.get_paginator("list_data_sources")
            for page in paginator.paginate(applicationId=application_id, indexId=index_id):
                index_data_sources.extend(page["dataSources"])

            for ds in index_data_sources:
                ds["region"] = region
                ds["applicationId"] = application_id
                ds["indexId"] = index_id
                ds["indexNodeId"] = index_node_id
                ds["id"] = f"{application_id}/{index_id}/{ds['dataSourceId']}"

            data_sources.extend(index_data_sources)
        except Exception as e:
            logger.warning(
                f"Could not list qbusiness data sources for application {application_id} "
                f"index {index_id}. skipping. - {e}",
            )
    return data_sources


@timeit
def load_qbusiness_data_sources(
    neo4j_session: neo4j.Session,
    data_sources: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_qbusiness_data_sources_tx, data_sources, current_aws_account_id, aws_update_tag)


@timeit
def _load_qbusiness_data_sources_tx(
    tx: neo4j.Transaction,
    data_sources: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_data_sources = """
    UNWIND $data_sources AS ds
    MERGE (i:AWSQBusinessDataSource{id:ds.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = ds.id,
    i.datasourceid = ds.dataSourceId
    SET i.name = ds.displayName,
    i.type = ds.type,
    i.status = ds.status,
    i.applicationid = ds.applicationId,
    i.indexid = ds.indexId,
    i.createdat = ds.createdAt,
    i.updatedat = ds.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = ds.region
    WITH i, ds
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, ds
    MATCH (index:AWSQBusinessIndex{id: ds.indexNodeId})
    MERGE (index)-[hds:HAS_DATA_SOURCE]->(i)
    ON CREATE SET hds.firstseen = timestamp()
    SET hds.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_data_sources,
        data_sources=data_sources,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_qbusiness_retrievers_list(
    boto3_session: boto3.session.Session,
    applications: List[Dict],
    region: str,
) -> List[Dict]:
    retrievers: List[Dict] = []
    client = get_boto3_client(boto3_session, "qbusiness", region)
    for app in applications:
        if app.get("region") != region:
            continue
        application_id = app["applicationId"]
        app_arn = app["arn"]
        try:
            app_retrievers: List[Dict] = []
            paginator = client.get_paginator("list_retrievers")
            for page in paginator.paginate(applicationId=application_id):
                app_retrievers.extend(page["retrievers"])

            for retriever in app_retrievers:
                retriever["region"] = region
                retriever["applicationId"] = application_id
                retriever["applicationArn"] = app_arn
                retriever["id"] = f"{application_id}/{retriever['retrieverId']}"

            retrievers.extend(app_retrievers)
        except Exception as e:
            logger.warning(
                f"Could not list qbusiness retrievers for application {application_id}. skipping. - {e}",
            )
    return retrievers


@timeit
def load_qbusiness_retrievers(
    neo4j_session: neo4j.Session,
    retrievers: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_qbusiness_retrievers_tx, retrievers, current_aws_account_id, aws_update_tag)


@timeit
def _load_qbusiness_retrievers_tx(
    tx: neo4j.Transaction,
    retrievers: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_retrievers = """
    UNWIND $retrievers AS retriever
    MERGE (i:AWSQBusinessRetriever{id:retriever.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = retriever.id,
    i.retrieverid = retriever.retrieverId
    SET i.name = retriever.displayName,
    i.type = retriever.type,
    i.status = retriever.status,
    i.applicationid = retriever.applicationId,
    i.lastupdated = $aws_update_tag,
    i.region = retriever.region
    WITH i, retriever
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, retriever
    MATCH (app:AWSQBusinessApplication{arn: retriever.applicationArn})
    MERGE (app)-[hr:HAS_RETRIEVER]->(i)
    ON CREATE SET hr.firstseen = timestamp()
    SET hr.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_retrievers,
        retrievers=retrievers,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def get_qbusiness_plugins_list(
    boto3_session: boto3.session.Session,
    applications: List[Dict],
    region: str,
) -> List[Dict]:
    plugins: List[Dict] = []
    client = get_boto3_client(boto3_session, "qbusiness", region)
    for app in applications:
        if app.get("region") != region:
            continue
        application_id = app["applicationId"]
        app_arn = app["arn"]
        try:
            app_plugins: List[Dict] = []
            paginator = client.get_paginator("list_plugins")
            for page in paginator.paginate(applicationId=application_id):
                app_plugins.extend(page["plugins"])

            for plugin in app_plugins:
                plugin["region"] = region
                plugin["applicationId"] = application_id
                plugin["applicationArn"] = app_arn
                plugin["id"] = f"{application_id}/{plugin['pluginId']}"

            plugins.extend(app_plugins)
        except Exception as e:
            logger.warning(
                f"Could not list qbusiness plugins for application {application_id}. skipping. - {e}",
            )
    return plugins


@timeit
def load_qbusiness_plugins(
    neo4j_session: neo4j.Session,
    plugins: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    neo4j_session.execute_write(_load_qbusiness_plugins_tx, plugins, current_aws_account_id, aws_update_tag)


@timeit
def _load_qbusiness_plugins_tx(
    tx: neo4j.Transaction,
    plugins: List[Dict],
    current_aws_account_id: str,
    aws_update_tag: int,
) -> None:
    ingest_plugins = """
    UNWIND $plugins AS plugin
    MERGE (i:AWSQBusinessPlugin{id:plugin.id})
    ON CREATE SET i.firstseen = timestamp(),
    i.id = plugin.id,
    i.pluginid = plugin.pluginId
    SET i.name = plugin.displayName,
    i.type = plugin.type,
    i.status = plugin.state,
    i.serverurl = plugin.serverUrl,
    i.applicationid = plugin.applicationId,
    i.createdat = plugin.createdAt,
    i.updatedat = plugin.updatedAt,
    i.lastupdated = $aws_update_tag,
    i.region = plugin.region
    WITH i, plugin
    MATCH (aa:AWSAccount{id: $AWS_ACCOUNT_ID})
    MERGE (aa)-[r:RESOURCE]->(i)
    ON CREATE SET r.firstseen = timestamp()
    SET r.lastupdated = $aws_update_tag
    WITH i, plugin
    MATCH (app:AWSQBusinessApplication{arn: plugin.applicationArn})
    MERGE (app)-[hp:HAS_PLUGIN]->(i)
    ON CREATE SET hp.firstseen = timestamp()
    SET hp.lastupdated = $aws_update_tag
    """

    tx.run(
        ingest_plugins,
        plugins=plugins,
        AWS_ACCOUNT_ID=current_aws_account_id,
        aws_update_tag=aws_update_tag,
    )


@timeit
def cleanup_qbusiness(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('aws_import_qbusiness_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync_qbusiness(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: str, current_aws_account_id: str,
    aws_update_tag: int, common_job_parameters: Dict,
) -> None:
    applications = []
    for region in regions:
        applications.extend(get_qbusiness_applications_list(boto3_session, current_aws_account_id, region))

    logger.info(f"Total qbusiness applications: {len(applications)}")

    load_qbusiness_applications(neo4j_session, applications, current_aws_account_id, aws_update_tag)

    # Indices are scoped to applications and must load before data sources.
    indices = []
    for region in regions:
        indices.extend(get_qbusiness_indices_list(boto3_session, applications, region))

    logger.info(f"Total qbusiness indices: {len(indices)}")

    load_qbusiness_indices(neo4j_session, indices, current_aws_account_id, aws_update_tag)

    data_sources = []
    for region in regions:
        data_sources.extend(get_qbusiness_data_sources_list(boto3_session, indices, region))

    logger.info(f"Total qbusiness data sources: {len(data_sources)}")

    load_qbusiness_data_sources(neo4j_session, data_sources, current_aws_account_id, aws_update_tag)

    retrievers = []
    for region in regions:
        retrievers.extend(get_qbusiness_retrievers_list(boto3_session, applications, region))

    logger.info(f"Total qbusiness retrievers: {len(retrievers)}")

    load_qbusiness_retrievers(neo4j_session, retrievers, current_aws_account_id, aws_update_tag)

    plugins = []
    for region in regions:
        plugins.extend(get_qbusiness_plugins_list(boto3_session, applications, region))

    logger.info(f"Total qbusiness plugins: {len(plugins)}")

    load_qbusiness_plugins(neo4j_session, plugins, current_aws_account_id, aws_update_tag)


@timeit
def sync(
    neo4j_session: neo4j.Session, boto3_session: boto3.session.Session, regions: List[str], current_aws_account_id: str,
    update_tag: int, common_job_parameters: Dict,
) -> None:
    tic = time.perf_counter()

    logger.info("Syncing QBusiness for account '%s', at %s.", current_aws_account_id, tic)
    sync_qbusiness(neo4j_session, boto3_session, regions, current_aws_account_id, update_tag, common_job_parameters)

    cleanup_qbusiness(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process QBusiness: {toc - tic:0.4f} seconds")
