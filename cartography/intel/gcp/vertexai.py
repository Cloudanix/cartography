import json
import logging
import time
from typing import Dict
from typing import List

import neo4j
from cloudconsolelink.clouds.gcp import GCPLinker
from googleapiclient.discovery import HttpError
from googleapiclient.discovery import Resource

from . import label
from cartography.util import run_cleanup_job
from cartography.util import timeit

logger = logging.getLogger(__name__)
gcp_console_link = GCPLinker()


def _handle_http_error(e: HttpError, resource_name: str, project_id: str, region: str) -> List[Dict]:
    """
    Downgrade GCP permission / forbidden errors to a warning and return an empty list so a single
    unauthorized region does not abort the whole sync. Any other error is re-raised.
    """
    err = json.loads(e.content.decode('utf-8'))['error']
    if err.get('status', '') == 'PERMISSION_DENIED' or err.get('message', '') == 'Forbidden':
        logger.warning(
            (
                "Could not retrieve Vertex AI %s on project %s region %s due to permissions issues. "
                "Code: %s, Message: %s"
            ), resource_name, project_id, region, err.get('code'), err.get('message'),
        )
        return []
    else:
        raise


def _parent(project_id: str, region: str) -> str:
    return f"projects/{project_id}/locations/{region}"


# ---------------------------------------------------------------------------
# MODELS
# ---------------------------------------------------------------------------
@timeit
def get_vertexai_models(vertexai: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    models: List[Dict] = []
    for region in regions:
        try:
            req = vertexai.projects().locations().models().list(parent=_parent(project_id, region))
            while req is not None:
                res = req.execute()
                for model in res.get('models', []):
                    model['region'] = region
                    model['id'] = model['name']
                    model['consolelink'] = gcp_console_link.get_console_link(
                        project_id=project_id, resource_name='vertex_ai_model',
                    )
                    models.append(model)
                req = vertexai.projects().locations().models().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            _handle_http_error(e, 'models', project_id, region)
    return models


@timeit
def load_vertexai_models(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.execute_write(_load_vertexai_models_tx, data_list, project_id, update_tag)


@timeit
def _load_vertexai_models_tx(tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    query = """
    UNWIND $Records as record
    MERGE (model:GCPVertexAIModel{id:record.id})
    ON CREATE SET
        model.firstseen = timestamp()
    SET
        model.lastupdated = $gcp_update_tag,
        model.name = record.name,
        model.display_name = record.displayName,
        model.region = record.region,
        model.version_id = record.versionId,
        model.artifact_uri = record.artifactUri,
        model.kms_key_name = record.encryptionSpec.kmsKeyName,
        model.create_time = record.createTime,
        model.update_time = record.updateTime,
        model.consolelink = record.consolelink
    WITH model
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(model)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


# ---------------------------------------------------------------------------
# ENDPOINTS
# ---------------------------------------------------------------------------
@timeit
def get_vertexai_endpoints(vertexai: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    endpoints: List[Dict] = []
    for region in regions:
        try:
            req = vertexai.projects().locations().endpoints().list(parent=_parent(project_id, region))
            while req is not None:
                res = req.execute()
                for endpoint in res.get('endpoints', []):
                    endpoint['region'] = region
                    endpoint['id'] = endpoint['name']
                    endpoint['deployed_model_ids'] = [
                        dm.get('model') for dm in endpoint.get('deployedModels', []) if dm.get('model')
                    ]
                    endpoint['consolelink'] = gcp_console_link.get_console_link(
                        project_id=project_id, resource_name='vertex_ai_endpoint',
                    )
                    endpoints.append(endpoint)
                req = vertexai.projects().locations().endpoints().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            _handle_http_error(e, 'endpoints', project_id, region)
    return endpoints


@timeit
def load_vertexai_endpoints(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.execute_write(_load_vertexai_endpoints_tx, data_list, project_id, update_tag)


@timeit
def _load_vertexai_endpoints_tx(tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    query = """
    UNWIND $Records as record
    MERGE (endpoint:GCPVertexAIEndpoint{id:record.id})
    ON CREATE SET
        endpoint.firstseen = timestamp()
    SET
        endpoint.lastupdated = $gcp_update_tag,
        endpoint.name = record.name,
        endpoint.display_name = record.displayName,
        endpoint.region = record.region,
        endpoint.network = record.network,
        endpoint.kms_key_name = record.encryptionSpec.kmsKeyName,
        endpoint.create_time = record.createTime,
        endpoint.update_time = record.updateTime,
        endpoint.consolelink = record.consolelink
    WITH endpoint, record
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(endpoint)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    WITH endpoint, record
    UNWIND record.deployed_model_ids as deployed_model_id
    MATCH (model:GCPVertexAIModel{id: deployed_model_id})
    MERGE (endpoint)-[dr:DEPLOYS]->(model)
    ON CREATE SET
        dr.firstseen = timestamp()
    SET dr.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


# ---------------------------------------------------------------------------
# DATASETS
# ---------------------------------------------------------------------------
@timeit
def get_vertexai_datasets(vertexai: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    datasets: List[Dict] = []
    for region in regions:
        try:
            req = vertexai.projects().locations().datasets().list(parent=_parent(project_id, region))
            while req is not None:
                res = req.execute()
                for dataset in res.get('datasets', []):
                    dataset['region'] = region
                    dataset['id'] = dataset['name']
                    dataset['consolelink'] = gcp_console_link.get_console_link(
                        project_id=project_id, resource_name='vertex_ai_dataset',
                    )
                    datasets.append(dataset)
                req = vertexai.projects().locations().datasets().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            _handle_http_error(e, 'datasets', project_id, region)
    return datasets


@timeit
def load_vertexai_datasets(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.execute_write(_load_vertexai_datasets_tx, data_list, project_id, update_tag)


@timeit
def _load_vertexai_datasets_tx(tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int) -> None:
    query = """
    UNWIND $Records as record
    MERGE (dataset:GCPVertexAIDataset{id:record.id})
    ON CREATE SET
        dataset.firstseen = timestamp()
    SET
        dataset.lastupdated = $gcp_update_tag,
        dataset.name = record.name,
        dataset.display_name = record.displayName,
        dataset.region = record.region,
        dataset.metadata_schema_uri = record.metadataSchemaUri,
        dataset.kms_key_name = record.encryptionSpec.kmsKeyName,
        dataset.create_time = record.createTime,
        dataset.update_time = record.updateTime,
        dataset.consolelink = record.consolelink
    WITH dataset
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(dataset)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


# ---------------------------------------------------------------------------
# CUSTOM JOBS
# ---------------------------------------------------------------------------
@timeit
def get_vertexai_custom_jobs(vertexai: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    jobs: List[Dict] = []
    for region in regions:
        try:
            req = vertexai.projects().locations().customJobs().list(parent=_parent(project_id, region))
            while req is not None:
                res = req.execute()
                for job in res.get('customJobs', []):
                    job['region'] = region
                    job['id'] = job['name']
                    job['service_account'] = job.get('jobSpec', {}).get('serviceAccount')
                    job['network'] = job.get('jobSpec', {}).get('network')
                    job['consolelink'] = gcp_console_link.get_console_link(
                        project_id=project_id, resource_name='vertex_ai_custom_job',
                    )
                    jobs.append(job)
                req = vertexai.projects().locations().customJobs().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            _handle_http_error(e, 'customJobs', project_id, region)
    return jobs


@timeit
def load_vertexai_custom_jobs(session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int) -> None:
    session.execute_write(_load_vertexai_custom_jobs_tx, data_list, project_id, update_tag)


@timeit
def _load_vertexai_custom_jobs_tx(
    tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int,
) -> None:
    query = """
    UNWIND $Records as record
    MERGE (job:GCPVertexAICustomJob{id:record.id})
    ON CREATE SET
        job.firstseen = timestamp()
    SET
        job.lastupdated = $gcp_update_tag,
        job.name = record.name,
        job.display_name = record.displayName,
        job.region = record.region,
        job.state = record.state,
        job.service_account = record.service_account,
        job.network = record.network,
        job.create_time = record.createTime,
        job.end_time = record.endTime,
        job.consolelink = record.consolelink
    WITH job
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(job)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


# ---------------------------------------------------------------------------
# TRAINING PIPELINES
# ---------------------------------------------------------------------------
@timeit
def get_vertexai_training_pipelines(vertexai: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    pipelines: List[Dict] = []
    for region in regions:
        try:
            req = vertexai.projects().locations().trainingPipelines().list(parent=_parent(project_id, region))
            while req is not None:
                res = req.execute()
                for pipeline in res.get('trainingPipelines', []):
                    pipeline['region'] = region
                    pipeline['id'] = pipeline['name']
                    pipeline['model_to_upload'] = pipeline.get('modelToUpload', {}).get('name')
                    pipeline['consolelink'] = gcp_console_link.get_console_link(
                        project_id=project_id, resource_name='vertex_ai_training_pipeline',
                    )
                    pipelines.append(pipeline)
                req = vertexai.projects().locations().trainingPipelines().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            _handle_http_error(e, 'trainingPipelines', project_id, region)
    return pipelines


@timeit
def load_vertexai_training_pipelines(
    session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int,
) -> None:
    session.execute_write(_load_vertexai_training_pipelines_tx, data_list, project_id, update_tag)


@timeit
def _load_vertexai_training_pipelines_tx(
    tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int,
) -> None:
    query = """
    UNWIND $Records as record
    MERGE (pipeline:GCPVertexAITrainingPipeline{id:record.id})
    ON CREATE SET
        pipeline.firstseen = timestamp()
    SET
        pipeline.lastupdated = $gcp_update_tag,
        pipeline.name = record.name,
        pipeline.display_name = record.displayName,
        pipeline.region = record.region,
        pipeline.state = record.state,
        pipeline.training_task_definition = record.trainingTaskDefinition,
        pipeline.create_time = record.createTime,
        pipeline.end_time = record.endTime,
        pipeline.consolelink = record.consolelink
    WITH pipeline, record
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(pipeline)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    WITH pipeline, record
    WHERE record.model_to_upload IS NOT NULL
    MATCH (model:GCPVertexAIModel{id: record.model_to_upload})
    MERGE (pipeline)-[pr:PRODUCES]->(model)
    ON CREATE SET
        pr.firstseen = timestamp()
    SET pr.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


# ---------------------------------------------------------------------------
# BATCH PREDICTION JOBS
# ---------------------------------------------------------------------------
@timeit
def get_vertexai_batch_prediction_jobs(vertexai: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    jobs: List[Dict] = []
    for region in regions:
        try:
            req = vertexai.projects().locations().batchPredictionJobs().list(parent=_parent(project_id, region))
            while req is not None:
                res = req.execute()
                for job in res.get('batchPredictionJobs', []):
                    job['region'] = region
                    job['id'] = job['name']
                    job['consolelink'] = gcp_console_link.get_console_link(
                        project_id=project_id, resource_name='vertex_ai_batch_prediction_job',
                    )
                    jobs.append(job)
                req = vertexai.projects().locations().batchPredictionJobs().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            _handle_http_error(e, 'batchPredictionJobs', project_id, region)
    return jobs


@timeit
def load_vertexai_batch_prediction_jobs(
    session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int,
) -> None:
    session.execute_write(_load_vertexai_batch_prediction_jobs_tx, data_list, project_id, update_tag)


@timeit
def _load_vertexai_batch_prediction_jobs_tx(
    tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int,
) -> None:
    query = """
    UNWIND $Records as record
    MERGE (job:GCPVertexAIBatchPredictionJob{id:record.id})
    ON CREATE SET
        job.firstseen = timestamp()
    SET
        job.lastupdated = $gcp_update_tag,
        job.name = record.name,
        job.display_name = record.displayName,
        job.region = record.region,
        job.state = record.state,
        job.model = record.model,
        job.create_time = record.createTime,
        job.end_time = record.endTime,
        job.consolelink = record.consolelink
    WITH job, record
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(job)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    WITH job, record
    WHERE record.model IS NOT NULL
    MATCH (model:GCPVertexAIModel{id: record.model})
    MERGE (job)-[ur:USES_MODEL]->(model)
    ON CREATE SET
        ur.firstseen = timestamp()
    SET ur.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


# ---------------------------------------------------------------------------
# PIPELINE JOBS
# ---------------------------------------------------------------------------
@timeit
def get_vertexai_pipeline_jobs(vertexai: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    jobs: List[Dict] = []
    for region in regions:
        try:
            req = vertexai.projects().locations().pipelineJobs().list(parent=_parent(project_id, region))
            while req is not None:
                res = req.execute()
                for job in res.get('pipelineJobs', []):
                    job['region'] = region
                    job['id'] = job['name']
                    job['consolelink'] = gcp_console_link.get_console_link(
                        project_id=project_id, resource_name='vertex_ai_pipeline_job',
                    )
                    jobs.append(job)
                req = vertexai.projects().locations().pipelineJobs().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            _handle_http_error(e, 'pipelineJobs', project_id, region)
    return jobs


@timeit
def load_vertexai_pipeline_jobs(
    session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int,
) -> None:
    session.execute_write(_load_vertexai_pipeline_jobs_tx, data_list, project_id, update_tag)


@timeit
def _load_vertexai_pipeline_jobs_tx(
    tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int,
) -> None:
    query = """
    UNWIND $Records as record
    MERGE (job:GCPVertexAIPipelineJob{id:record.id})
    ON CREATE SET
        job.firstseen = timestamp()
    SET
        job.lastupdated = $gcp_update_tag,
        job.name = record.name,
        job.display_name = record.displayName,
        job.region = record.region,
        job.state = record.state,
        job.service_account = record.serviceAccount,
        job.network = record.network,
        job.create_time = record.createTime,
        job.end_time = record.endTime,
        job.consolelink = record.consolelink
    WITH job
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(job)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


# ---------------------------------------------------------------------------
# REASONING ENGINES (Agent Engine)
# ---------------------------------------------------------------------------
@timeit
def get_vertexai_reasoning_engines(vertexai: Resource, project_id: str, regions: List[str]) -> List[Dict]:
    engines: List[Dict] = []
    for region in regions:
        try:
            req = vertexai.projects().locations().reasoningEngines().list(parent=_parent(project_id, region))
            while req is not None:
                res = req.execute()
                for engine in res.get('reasoningEngines', []):
                    engine['region'] = region
                    engine['id'] = engine['name']
                    engine['consolelink'] = gcp_console_link.get_console_link(
                        project_id=project_id, resource_name='vertex_ai_reasoning_engine',
                    )
                    engines.append(engine)
                req = vertexai.projects().locations().reasoningEngines().list_next(
                    previous_request=req, previous_response=res,
                )
        except HttpError as e:
            _handle_http_error(e, 'reasoningEngines', project_id, region)
    return engines


@timeit
def load_vertexai_reasoning_engines(
    session: neo4j.Session, data_list: List[Dict], project_id: str, update_tag: int,
) -> None:
    session.execute_write(_load_vertexai_reasoning_engines_tx, data_list, project_id, update_tag)


@timeit
def _load_vertexai_reasoning_engines_tx(
    tx: neo4j.Transaction, data: List[Dict], project_id: str, gcp_update_tag: int,
) -> None:
    query = """
    UNWIND $Records as record
    MERGE (engine:GCPVertexAIReasoningEngine{id:record.id})
    ON CREATE SET
        engine.firstseen = timestamp()
    SET
        engine.lastupdated = $gcp_update_tag,
        engine.name = record.name,
        engine.display_name = record.displayName,
        engine.region = record.region,
        engine.description = record.description,
        engine.create_time = record.createTime,
        engine.update_time = record.updateTime,
        engine.consolelink = record.consolelink
    WITH engine
    MATCH (owner:GCPProject{id: $ProjectId})
    MERGE (owner)-[r:RESOURCE]->(engine)
    ON CREATE SET
        r.firstseen = timestamp()
    SET r.lastupdated = $gcp_update_tag
    """
    tx.run(query, Records=data, ProjectId=project_id, gcp_update_tag=gcp_update_tag)


# ---------------------------------------------------------------------------
# CLEANUP + SYNC
# ---------------------------------------------------------------------------
@timeit
def cleanup_vertexai(neo4j_session: neo4j.Session, common_job_parameters: Dict) -> None:
    run_cleanup_job('gcp_vertexai_cleanup.json', neo4j_session, common_job_parameters)


@timeit
def sync(
    neo4j_session: neo4j.Session, vertexai: Resource, project_id: str, gcp_update_tag: int,
    common_job_parameters: Dict, regions: list,
) -> None:
    """
    Get GCP Vertex AI resources using the aiplatform resource object, ingest to Neo4j, and clean up old data.
    """
    tic = time.perf_counter()
    logger.info("Syncing Vertex AI for project '%s', at %s.", project_id, tic)

    # MODELS - loaded first so endpoint/pipeline/job relationships can resolve.
    models = get_vertexai_models(vertexai, project_id, regions)
    load_vertexai_models(neo4j_session, models, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, models, gcp_update_tag, common_job_parameters,
        'vertex ai models', 'GCPVertexAIModel',
    )

    # DATASETS
    datasets = get_vertexai_datasets(vertexai, project_id, regions)
    load_vertexai_datasets(neo4j_session, datasets, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, datasets, gcp_update_tag, common_job_parameters,
        'vertex ai datasets', 'GCPVertexAIDataset',
    )

    # ENDPOINTS
    endpoints = get_vertexai_endpoints(vertexai, project_id, regions)
    load_vertexai_endpoints(neo4j_session, endpoints, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, endpoints, gcp_update_tag, common_job_parameters,
        'vertex ai endpoints', 'GCPVertexAIEndpoint',
    )

    # CUSTOM JOBS
    custom_jobs = get_vertexai_custom_jobs(vertexai, project_id, regions)
    load_vertexai_custom_jobs(neo4j_session, custom_jobs, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, custom_jobs, gcp_update_tag, common_job_parameters,
        'vertex ai custom jobs', 'GCPVertexAICustomJob',
    )

    # TRAINING PIPELINES
    training_pipelines = get_vertexai_training_pipelines(vertexai, project_id, regions)
    load_vertexai_training_pipelines(neo4j_session, training_pipelines, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, training_pipelines, gcp_update_tag, common_job_parameters,
        'vertex ai training pipelines', 'GCPVertexAITrainingPipeline',
    )

    # BATCH PREDICTION JOBS
    batch_prediction_jobs = get_vertexai_batch_prediction_jobs(vertexai, project_id, regions)
    load_vertexai_batch_prediction_jobs(neo4j_session, batch_prediction_jobs, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, batch_prediction_jobs, gcp_update_tag, common_job_parameters,
        'vertex ai batch prediction jobs', 'GCPVertexAIBatchPredictionJob',
    )

    # PIPELINE JOBS
    pipeline_jobs = get_vertexai_pipeline_jobs(vertexai, project_id, regions)
    load_vertexai_pipeline_jobs(neo4j_session, pipeline_jobs, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, pipeline_jobs, gcp_update_tag, common_job_parameters,
        'vertex ai pipeline jobs', 'GCPVertexAIPipelineJob',
    )

    # REASONING ENGINES (Agent Engine)
    reasoning_engines = get_vertexai_reasoning_engines(vertexai, project_id, regions)
    load_vertexai_reasoning_engines(neo4j_session, reasoning_engines, project_id, gcp_update_tag)
    label.sync_labels(
        neo4j_session, reasoning_engines, gcp_update_tag, common_job_parameters,
        'vertex ai reasoning engines', 'GCPVertexAIReasoningEngine',
    )

    cleanup_vertexai(neo4j_session, common_job_parameters)

    toc = time.perf_counter()
    logger.info(f"Time to process Vertex AI: {toc - tic:0.4f} seconds")
