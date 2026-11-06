import cartography.intel.gcp.vertexai as vertexai

TEST_UPDATE_TAG = 123456789
PROJECT_A = 'vertex-tenant-a'
PROJECT_B = 'vertex-tenant-b'
REGION = 'us-central1'
OTHER_REGION = 'europe-west4'


def _model(project_id: str, region: str, short_id: str) -> dict:
    name = f'projects/{project_id}/locations/{region}/models/{short_id}'
    return {'id': name, 'name': name, 'region': region}


OWN_MODEL = _model(PROJECT_A, REGION, '1')
OWN_MODEL_OTHER_REGION = _model(PROJECT_A, OTHER_REGION, '1')
FOREIGN_MODEL = _model(PROJECT_B, REGION, '1')


def _seed(neo4j_session):
    for project_id in (PROJECT_A, PROJECT_B):
        neo4j_session.run('MERGE (:GCPProject{id: $id})', id=project_id)
    vertexai.load_vertexai_models(neo4j_session, [OWN_MODEL, OWN_MODEL_OTHER_REGION], PROJECT_A, TEST_UPDATE_TAG)
    vertexai.load_vertexai_models(neo4j_session, [FOREIGN_MODEL], PROJECT_B, TEST_UPDATE_TAG)


def _linked_models(neo4j_session, label: str, rel: str) -> set:
    rows = neo4j_session.run(
        f'MATCH (:GCPProject{{id: $p}})-[:RESOURCE]->(:{label})-[:{rel}]->(m:GCPVertexAIModel) RETURN m.id AS id',
        p=PROJECT_A,
    )
    return {r['id'] for r in rows}


def test_model_links_stay_in_the_syncing_project(neo4j_session):
    """
    Project A's endpoint, training pipeline and batch job reference its own model and a model owned by
    project B (a foreign id, AGENTS.md rule 4). Only A's own model is linked; B's model and A's same-named
    model in another region get no edge.
    """
    _seed(neo4j_session)
    refs = [f"{OWN_MODEL['id']}@2", f"{FOREIGN_MODEL['id']}@1"]

    vertexai.load_vertexai_endpoints(
        neo4j_session, [{
            'id': 'ep-a', 'name': 'ep-a', 'region': REGION, 'deployed_model_ids': [
                vertexai._model_id(r) for r in refs
            ],
        }], PROJECT_A, TEST_UPDATE_TAG,
    )
    vertexai.load_vertexai_training_pipelines(
        neo4j_session, [
            {'id': f'tp-a-{i}', 'name': f'tp-a-{i}', 'region': REGION, 'model_to_upload': vertexai._model_id(r)}
            for i, r in enumerate(refs)
        ], PROJECT_A, TEST_UPDATE_TAG,
    )
    vertexai.load_vertexai_batch_prediction_jobs(
        neo4j_session, [
            {'id': f'bj-a-{i}', 'name': f'bj-a-{i}', 'region': REGION, 'model': r, 'model_id': vertexai._model_id(r)}
            for i, r in enumerate(refs)
        ], PROJECT_A, TEST_UPDATE_TAG,
    )

    expected = {OWN_MODEL['id']}
    assert _linked_models(neo4j_session, 'GCPVertexAIEndpoint', 'DEPLOYS') == expected
    assert _linked_models(neo4j_session, 'GCPVertexAITrainingPipeline', 'PRODUCES') == expected
    assert _linked_models(neo4j_session, 'GCPVertexAIBatchPredictionJob', 'USES_MODEL') == expected
    foreign_edges = neo4j_session.run(
        'MATCH (:GCPProject{id: $b})-[:RESOURCE]->(m:GCPVertexAIModel)<-[r]-() RETURN count(r) AS c', b=PROJECT_B,
    ).single()['c']
    assert foreign_edges == 0
