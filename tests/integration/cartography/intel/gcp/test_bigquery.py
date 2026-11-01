import cartography.intel.gcp.bigquery
import tests.data.gcp.bigquery
from cartography.intel.gcp.exposure_layers import access
from cartography.util import run_analysis_job
TEST_PROJECT_NUMBER = '000000000000'
TEST_UPDATE_TAG = 123456789
TEST_REGION = 'us-east-1a'
TEST_DATASET_ID = 'dataset1'

TEST_WORKSPACE_ID = '1223344'


common_job_parameters = {
    "UPDATE_TAG": TEST_UPDATE_TAG,
    "WORKSPACE_ID": '1223344',
    "GCP_PROJECT_ID": TEST_PROJECT_NUMBER,
}


def cloudanix_workspace_to_gcp_project(neo4j_session):
    query = """
    MERGE (w:CloudanixWorkspace{id: $WorkspaceId})
    MERGE (project:GCPProject{id: $ProjectId})
    MERGE (w)-[:OWNER]->(project)
    """
    nodes = neo4j_session.run(
        query,
        WorkspaceId=TEST_WORKSPACE_ID,
        ProjectId=TEST_PROJECT_NUMBER,
    )


def test_load_bigquey_dataset(neo4j_session):
    data = tests.data.gcp.bigquery.TEST_DATASET
    cartography.intel.gcp.bigquery.load_bigquery_datasets(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "dataset1",
        "dataset2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPBigqueryDataset) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_bigquery_tables(neo4j_session):
    data = tests.data.gcp.bigquery.TEST_TABLE
    cartography.intel.gcp.bigquery.load_bigquery_tables(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "table1",
        "table2",
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPBigqueryTable) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_bigquery_dataset_relationship(neo4j_session):
    # Create Test GCPProject
    neo4j_session.run(
        """
        MERGE (gcp:GCPProject{id: $PROJECT_NUMBER})
        ON CREATE SET gcp.firstseen = timestamp()
        SET gcp.lastupdated = $UPDATE_TAG
        """,
        PROJECT_NUMBER=TEST_PROJECT_NUMBER,
        UPDATE_TAG=TEST_UPDATE_TAG,
    )

    # Load GCP Bigquery Dataset
    data = tests.data.gcp.bigquery.TEST_DATASET
    cartography.intel.gcp.bigquery.load_bigquery_datasets(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        (TEST_PROJECT_NUMBER, 'dataset1'),
        (TEST_PROJECT_NUMBER, 'dataset2'),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPProject)-[:RESOURCE]->(n2:GCPBigqueryDataset) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_bigquey_dataset_table_relationship(neo4j_session):
    # Load Big Query Dataset
    data = tests.data.gcp.bigquery.TEST_DATASET
    cartography.intel.gcp.bigquery.load_bigquery_datasets(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    # Load Bigquery Table
    data = tests.data.gcp.bigquery.TEST_TABLE
    cartography.intel.gcp.bigquery.load_bigquery_tables(
        neo4j_session,
        data,
        TEST_PROJECT_NUMBER,
        TEST_UPDATE_TAG,
    )

    expected = {
        ('dataset1', 'table1'),
        ('dataset2', 'table2'),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:GCPBigqueryDataset)-[:HAS_TABLE]->(n2:GCPBigqueryTable) RETURN n1.id, n2.id;
        """,
    )

    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }

    assert actual == expected


def test_cloud_function(neo4j_session):
    cloudanix_workspace_to_gcp_project(neo4j_session)
    data = tests.data.gcp.bigquery.TEST_DATASET
    cartography.intel.gcp.bigquery.load_bigquery_datasets(neo4j_session, data, TEST_PROJECT_NUMBER, TEST_UPDATE_TAG)
    accesses_data = tests.data.gcp.bigquery.TEST_ACCESSES

    cartography.intel.gcp.bigquery.attach_dataset_to_accesses(neo4j_session, TEST_DATASET_ID, accesses_data, TEST_UPDATE_TAG)

    query1 = """
    MATCH (access:GCPAcl)-[a:APPLIES_TO]->(dataset:GCPBigqueryDataset)<-[:RESOURCE]-(:GCPProject{id: $GCP_PROJECT_ID})<-[:OWNER]-(:GCPOrganization{id:$GCP_ORGANIZATION_ID})<-[:OWNER]-(:CloudanixWorkspace{id: $WORKSPACE_ID}) \nWHERE dataset.exposed_internet=true
    RETURN dataset.id,dataset.exposed_internet,dataset.exposed_internet_type
    """
    run_analysis_job('gcp_bigquery_dataset_analysis.json', neo4j_session, common_job_parameters)

    objects1 = neo4j_session.run(query1, GCP_PROJECT_ID=TEST_PROJECT_NUMBER, WORKSPACE_ID=TEST_WORKSPACE_ID)

    actual_nodes = {
        (
            o['dataset.id'],
            o['dataset.exposed_internet'],
            ",".join(o['dataset.exposed_internet_type']),

        ) for o in objects1

    }

    expected_nodes = {

        (
            'dataset1',
            True,
            'allAuthenticatedUsers',
        ),

    }

    assert actual_nodes == expected_nodes


BQ_PARAMS = {
    'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': 'ws-bq', 'GCP_ORGANIZATION_ID': 'org-bq',
    'GCP_PROJECT_ID': 'proj-bq', 'LIMIT_SIZE': 1000,
}


def test_dataset_exposure_reads_iam_members_and_special_groups(neo4j_session):
    project = BQ_PARAMS['GCP_PROJECT_ID']
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:GCPOrganization{id: $org})-[:OWNER]->(:GCPProject{id: $p})",
        ws=BQ_PARAMS['WORKSPACE_ID'], org=BQ_PARAMS['GCP_ORGANIZATION_ID'], p=project,
    )
    accesses = {
        # datasets.get returns allUsers as an iamMember entry; allAuthenticatedUsers is a specialGroup.
        'bq-all-users': [{'role': 'READER', 'iamMember': 'allUsers'}],
        'bq-all-authenticated': [{'role': 'READER', 'specialGroup': 'allAuthenticatedUsers'}],
        # Same role for an ordinary user and allUsers: both entries must survive.
        'bq-shared-role': [{'role': 'READER', 'iamMember': 'allUsers'}, {'role': 'READER', 'userByEmail': 'a@x.io'}],
        'bq-private': [
            {'role': 'READER', 'specialGroup': 'projectReaders'}, {'role': 'OWNER', 'userByEmail': 'a@x.io'},
        ],
    }
    datasets = [{'id': d, 'uniqueId': f'projects/{project}/datasets/{d}', 'details': {}} for d in accesses]
    cartography.intel.gcp.bigquery.load_bigquery_datasets(neo4j_session, datasets, project, TEST_UPDATE_TAG)
    for dataset_id, entries in accesses.items():
        rows = cartography.intel.gcp.bigquery.transform_dataset_accesses(entries, dataset_id, project)
        cartography.intel.gcp.bigquery.attach_dataset_to_accesses(neo4j_session, dataset_id, rows, TEST_UPDATE_TAG)
    cartography.intel.gcp.bigquery.load_bigquery_tables(
        neo4j_session, [
            {'id': f'{d}-table', 'uniqueId': f'{d}-table', 'datasetId': d, 'details': {}}
            for d in ('bq-all-users', 'bq-private')
        ], project, TEST_UPDATE_TAG,
    )
    # A table flagged while its dataset was public; the dataset is private now.
    neo4j_session.run(
        "MATCH (t:GCPBigqueryTable{id: 'bq-private-table'}) "
        "SET t.exposed_internet = true, t.exposed_internet_type = ['allUsers']",
    )

    run_analysis_job('gcp_bigquery_dataset_analysis.json', neo4j_session, BQ_PARAMS)

    rows = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $p})-[:RESOURCE]->(d:GCPBigqueryDataset)
        OPTIONAL MATCH (d)-[:HAS_TABLE]->(t:GCPBigqueryTable)
        WITH [n IN [d, t] WHERE n IS NOT NULL AND n.exposed_internet] AS exposed
        UNWIND exposed AS n
        RETURN n.id AS id, n.exposed_internet_type AS types
        """,
        p=project,
    )
    assert {r['id']: r['types'] for r in rows} == {
        'bq-all-users': ['allUsers'],
        'bq-all-users-table': ['allUsers'],
        'bq-all-authenticated': ['allAuthenticatedUsers'],
        'bq-shared-role': ['allUsers'],
    }


def test_unread_dataset_access_keeps_entries_and_reads_unknown(neo4j_session, mocker):
    project = 'proj-bq-unread'
    params = {**BQ_PARAMS, 'GCP_PROJECT_ID': project, 'service_labels': []}
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:GCPOrganization{id: $org})-[:OWNER]->(:GCPProject{id: $p})",
        ws=params['WORKSPACE_ID'], org=params['GCP_ORGANIZATION_ID'], p=project,
    )
    module = cartography.intel.gcp.bigquery
    mocker.patch.object(
        module, 'get_bigquery_dataset',
        return_value=[{'datasetReference': {'datasetId': d}} for d in ('bq-read', 'bq-unread')],
    )
    mocker.patch.object(module, 'get_dataset_info', return_value={})
    mocker.patch.object(module, 'get_bigquery_tables', return_value=[])
    mocker.patch.object(module.gcp_console_link, 'get_console_link', return_value='link')

    def sync(tag, entries):
        mocker.patch.object(module, 'get_dataset_access_info', side_effect=lambda _b, d, _p: entries[d]())
        module.sync(neo4j_session, None, project, tag, {**params, 'UPDATE_TAG': tag}, [])

    def open_access():
        return [{'role': 'READER', 'iamMember': 'allUsers'}]

    sync(TEST_UPDATE_TAG, {'bq-read': open_access, 'bq-unread': open_access})
    # Next sync: bq-read no longer grants allUsers; bq-unread's datasets.get is denied.
    sync(TEST_UPDATE_TAG + 1, {'bq-read': list, 'bq-unread': lambda: None})

    rows = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $p})-[:RESOURCE]->(d:GCPBigqueryDataset)
        OPTIONAL MATCH (a:GCPAcl)-[:APPLIES_TO]->(d)
        RETURN d.id AS id, d.iam_policy_status AS status, collect(a.iam_member) AS members
        """,
        p=project,
    )
    assert {r['id']: (r['status'], r['members']) for r in rows} == {
        'bq-read': ('resolved', []),
        'bq-unread': ('unresolved', ['allUsers']),
    }
    auth = access.compute(neo4j_session, params)['GCPBigqueryDataset']
    assert auth['bq-read']['access_auth'] == 'required'
    assert (auth['bq-unread']['access_auth'], auth['bq-unread']['access_auth_reasons']) == (
        'unknown', ['dataset_access_not_read'],
    )
