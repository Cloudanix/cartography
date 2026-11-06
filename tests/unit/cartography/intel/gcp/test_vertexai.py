from unittest.mock import MagicMock

import googleapiclient.discovery
import pytest
from googleapiclient.http import HttpMock

from cartography.intel.gcp import vertexai

PROJECT_ID = 'p1'
REGION = 'us-central1'

# (collector, aiplatform collection, response key)
COLLECTORS = [
    (vertexai.get_vertexai_models, 'models', 'models'),
    (vertexai.get_vertexai_endpoints, 'endpoints', 'endpoints'),
    (vertexai.get_vertexai_datasets, 'datasets', 'datasets'),
    (vertexai.get_vertexai_custom_jobs, 'customJobs', 'customJobs'),
    (vertexai.get_vertexai_training_pipelines, 'trainingPipelines', 'trainingPipelines'),
    (vertexai.get_vertexai_batch_prediction_jobs, 'batchPredictionJobs', 'batchPredictionJobs'),
    (vertexai.get_vertexai_pipeline_jobs, 'pipelineJobs', 'pipelineJobs'),
    (vertexai.get_vertexai_reasoning_engines, 'reasoningEngines', 'reasoningEngines'),
]


def _stub_client(collection: str, response: dict) -> MagicMock:
    client = MagicMock()
    resource = getattr(client.projects.return_value.locations.return_value, collection).return_value
    resource.list.return_value.execute.return_value = response
    resource.list_next.return_value = None
    return client


@pytest.mark.parametrize('collector,collection,key', COLLECTORS)
def test_collector_returns_one_item_with_console_link(collector, collection, key):
    name = f'projects/{PROJECT_ID}/locations/{REGION}/{collection}/123'
    client = _stub_client(collection, {key: [{'name': name}]})

    items = collector({REGION: client}, PROJECT_ID)

    assert len(items) == 1
    assert items[0]['id'] == name
    assert items[0]['region'] == REGION
    assert items[0]['consolelink'].startswith('https://console.cloud.google.com/vertex-ai')


def test_regional_client_targets_locational_endpoint():
    global_client = googleapiclient.discovery.build('aiplatform', 'v1', http=HttpMock(), cache_discovery=False)

    client = vertexai._regional_client(global_client, 'europe-west4')
    req = client.projects().locations().models().list(parent=f'projects/{PROJECT_ID}/locations/europe-west4')

    assert req.uri.startswith('https://europe-west4-aiplatform.googleapis.com/v1/projects/p1/locations/europe-west4/')
    assert client._http is global_client._http
