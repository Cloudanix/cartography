from cartography.intel.gcp import bigquery
from cartography.intel.gcp import dataflow
from cartography.intel.gcp.exposure_layers import access
from cartography.util import run_analysis_job

TEST_UPDATE_TAG = 123456789
# Two customers whose projects both hold a dataset "billing_export" with a table "events" (the billing export
# and Airbyte defaults: every tenant has them).
PROJECT, OTHER_PROJECT = 'proj-bqt-a', 'proj-bqt-b'
DATASET, TABLE = 'billing_export', 'events'


def _params(project):
    suffix = project[-1]
    return {
        'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': f'ws-bqt-{suffix}', 'GCP_ORGANIZATION_ID': f'org-bqt-{suffix}',
        'GCP_PROJECT_ID': project, 'LIMIT_SIZE': 1000, 'service_labels': [],
    }


def _dataset_id(project):
    return f'projects/{project}/datasets/{DATASET}'


def _table_id(project):
    return f'{_dataset_id(project)}/tables/{TABLE}'


def _sync(neo4j_session, mocker, project, access_entries):
    params = _params(project)
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:GCPOrganization{id: $org})-[:OWNER]->(:GCPProject{id: $p})",
        ws=params['WORKSPACE_ID'], org=params['GCP_ORGANIZATION_ID'], p=project,
    )
    module = bigquery
    mocker.patch.object(
        module, 'get_bigquery_dataset', side_effect=lambda *_: [{'datasetReference': {'datasetId': DATASET}}],
    )
    mocker.patch.object(module, 'get_dataset_info', return_value={})
    mocker.patch.object(module, 'get_dataset_access_info', side_effect=lambda *_: list(access_entries))
    mocker.patch.object(module, 'get_bigquery_tables', side_effect=lambda *_: [{'tableReference': {'tableId': TABLE}}])
    mocker.patch.object(module, 'get_table_info', return_value={})
    mocker.patch.object(module.gcp_console_link, 'get_console_link', return_value='link')
    module.sync(neo4j_session, None, project, TEST_UPDATE_TAG, params, [])


def _rows(neo4j_session, query, **kwargs):
    return {tuple(r.values()) for r in neo4j_session.run(query, **kwargs)}


def test_same_dataset_and_table_name_in_two_tenants_stay_apart(neo4j_session, mocker):
    _sync(neo4j_session, mocker, PROJECT, [{'role': 'READER', 'iamMember': 'allUsers'}])
    _sync(neo4j_session, mocker, OTHER_PROJECT, [{'role': 'OWNER', 'userByEmail': 'admin@b.example'}])

    for project in (PROJECT, OTHER_PROJECT):
        # One dataset and one table per project, owned by that project only.
        assert _rows(
            neo4j_session,
            """
            MATCH (:GCPProject{id: $p})-[:RESOURCE]->(d:GCPBigqueryDataset)-[:HAS_TABLE]->(t:GCPBigqueryTable)
            RETURN d.id, d.name, t.id, t.name
            """,
            p=project,
        ) == {(_dataset_id(project), DATASET, _table_id(project), TABLE)}
    assert _rows(
        neo4j_session,
        """
        MATCH (p:GCPProject)-[:RESOURCE]->(d:GCPBigqueryDataset) WHERE p.id IN $projects
        WITH d, count(p) AS owners WHERE owners > 1 RETURN d.id
        """,
        projects=[PROJECT, OTHER_PROJECT],
    ) == set()

    # The other tenant's grants never land on this tenant's dataset, and its exposure is its own.
    for project in (PROJECT, OTHER_PROJECT):
        run_analysis_job('gcp_bigquery_dataset_analysis.json', neo4j_session, _params(project))
    assert _rows(
        neo4j_session,
        "MATCH (a:GCPAcl)-[:APPLIES_TO]->(:GCPBigqueryDataset{id: $d}) RETURN a.id", d=_dataset_id(OTHER_PROJECT),
    ) == {(f'projects/{OTHER_PROJECT}/bigquery/{DATASET}/role/OWNER/userByEmail/admin@b.example',)}
    assert _rows(
        neo4j_session,
        "MATCH (n) WHERE n.id IN $ids RETURN n.id, coalesce(n.exposed_internet, false)",
        ids=[_dataset_id(PROJECT), _table_id(PROJECT), _dataset_id(OTHER_PROJECT), _table_id(OTHER_PROJECT)],
    ) == {
        (_dataset_id(PROJECT), True), (_table_id(PROJECT), True),
        (_dataset_id(OTHER_PROJECT), False), (_table_id(OTHER_PROJECT), False),
    }
    auth = access.compute(neo4j_session, _params(OTHER_PROJECT))['GCPBigqueryDataset']
    assert auth[_dataset_id(OTHER_PROJECT)]['access_auth'] == 'required'


def test_dataflow_job_references_tables_only_inside_its_org(neo4j_session, mocker):
    _sync(neo4j_session, mocker, PROJECT, [])
    _sync(neo4j_session, mocker, OTHER_PROJECT, [])
    # The loader chains its UNWINDs, so a job only reaches the BigQuery step when its Bigtable tables resolve.
    neo4j_session.run("MERGE (:GCPBigtableTable{id: 'projects/proj-bqt-a/instances/i/tables/t'})")
    job = {
        'id': 'job-bqt', 'name': 'job-bqt', 'environment': {},
        'bigTables': ['projects/proj-bqt-a/instances/i/tables/t'],
        # A job may read or write any project's table, including another customer's.
        'bigQueries': [_table_id(PROJECT), _table_id(OTHER_PROJECT)],
        'pubSub': [], 'spannerDatabases': [],
    }

    dataflow.load_dataflow_jobs(neo4j_session, [job], PROJECT, TEST_UPDATE_TAG, _params(PROJECT))

    assert _rows(
        neo4j_session, "MATCH (:GCPDataFlowJob{id: 'job-bqt'})-[:REFERENCES]->(t:GCPBigqueryTable) RETURN t.id",
    ) == {(_table_id(PROJECT),)}
