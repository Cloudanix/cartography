import cartography.intel.gcp.bigquery
import cartography.intel.gcp.bigtable
import cartography.intel.gcp.dataflow
import cartography.intel.gcp.pubsub
import cartography.intel.gcp.spanner
import tests.data.gcp.bigquery
import tests.data.gcp.bigtable
import tests.data.gcp.dataflow
import tests.data.gcp.pubsub
import tests.data.gcp.spanner

TEST_PROJECT_ID = 'project-123'
TEST_UPDATE_TAG = 123456789
COMMON_JOB_PARAMETERS = {'WORKSPACE_ID': 'ws-dataflow', 'GCP_ORGANIZATION_ID': 'org-dataflow'}
DATASET_PREFIX = f'projects/{TEST_PROJECT_ID}/datasets'


def _seed_org(neo4j_session):
    # References are followed only to targets under a project of the syncing organization: the job's project
    # holds them here, Bigtable tables and Spanner databases under their instances.
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:GCPOrganization{id: $org})-[:OWNER]->(p:GCPProject{id: $p})
        FOREACH (i IN ['instance123', 'instance456'] | MERGE (p)-[:RESOURCE]->(:GCPBigtableInstance{id: i}))
        FOREACH (i IN ['instance1', 'instance2'] |
            MERGE (p)-[:RESOURCE]->(:GCPSpannerInstance{id: 'projects/' + $p + '/instances/' + i}))
        """,
        ws=COMMON_JOB_PARAMETERS['WORKSPACE_ID'], org=COMMON_JOB_PARAMETERS['GCP_ORGANIZATION_ID'], p=TEST_PROJECT_ID,
    )


def test_dataflow_jobs(neo4j_session):
    _seed_org(neo4j_session)
    data = tests.data.gcp.dataflow.TEST_DATAFLOW_JOBS
    cartography.intel.gcp.dataflow.load_dataflow_jobs(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
        COMMON_JOB_PARAMETERS,
    )
    expected_nodes = {
        'job1',
    }

    nodes = neo4j_session.run(
        """
        MATCH (r:GCPDataFlowJob) RETURN r.id;
        """,
    )

    actual_nodes = {n['r.id'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_dataflow_job_bigtable_relation(neo4j_session):
    _seed_org(neo4j_session)
    data = tests.data.gcp.bigtable.BIGTABLE_TABLE
    cartography.intel.gcp.bigtable.load_bigtable_tables(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
    )
    data = tests.data.gcp.dataflow.TEST_DATAFLOW_JOBS
    cartography.intel.gcp.dataflow.load_dataflow_jobs(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
        COMMON_JOB_PARAMETERS,
    )
    expected_nodes = {
        ('job1', 'table123'), ('job1', 'table456'),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:GCPDataFlowJob)-[:REFERENCES]->(m:GCPBigtableTable) RETURN n.id,m.id;
        """,
    )

    actual_nodes = {(n['n.id'], n['m.id']) for n in nodes}

    assert actual_nodes == expected_nodes


def test_dataflow_job_bigquery_relation(neo4j_session):
    _seed_org(neo4j_session)
    # Tables are followed only inside the syncing org, so they hang off a project of it.
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:GCPOrganization{id: $org})-[:OWNER]->(:GCPProject{id: $p})",
        ws=COMMON_JOB_PARAMETERS['WORKSPACE_ID'], org=COMMON_JOB_PARAMETERS['GCP_ORGANIZATION_ID'], p=TEST_PROJECT_ID,
    )
    datasets = [{'id': f'{DATASET_PREFIX}/{d}', 'name': d, 'details': {}} for d in ('dataset1', 'dataset2')]
    cartography.intel.gcp.bigquery.load_bigquery_datasets(neo4j_session, datasets, TEST_PROJECT_ID, TEST_UPDATE_TAG)
    data = [
        {**t, 'id': f'{DATASET_PREFIX}/{d}/tables/{t["name"]}', 'datasetId': f'{DATASET_PREFIX}/{d}'}
        for t, d in zip(tests.data.gcp.bigquery.TEST_TABLE, ('dataset1', 'dataset2'))
    ]
    cartography.intel.gcp.bigquery.load_bigquery_tables(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
    )
    data = tests.data.gcp.dataflow.TEST_DATAFLOW_JOBS
    cartography.intel.gcp.dataflow.load_dataflow_jobs(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
        COMMON_JOB_PARAMETERS,
    )
    expected_nodes = {
        ('job1', f'{DATASET_PREFIX}/dataset2/tables/table2'), ('job1', f'{DATASET_PREFIX}/dataset1/tables/table1'),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:GCPDataFlowJob)-[:REFERENCES]->(m:GCPBigqueryTable) RETURN n.id,m.id;
        """,
    )

    actual_nodes = {(n['n.id'], n['m.id']) for n in nodes}

    assert actual_nodes == expected_nodes


def test_dataflow_job_pubsub_relation(neo4j_session):
    _seed_org(neo4j_session)
    data = tests.data.gcp.pubsub.TEST_TOPICS
    cartography.intel.gcp.pubsub.load_pubsub_topics(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
    )
    # pubsub.py attaches a subscription to its project only through its topic.
    data = [{**s, 'topic': 'projects/project123/topic/topic123'} for s in tests.data.gcp.pubsub.TEST_SUBCRIPTIONS]
    cartography.intel.gcp.pubsub.load_pubsub_subscriptions(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
    )
    data = tests.data.gcp.dataflow.TEST_DATAFLOW_JOBS
    cartography.intel.gcp.dataflow.load_dataflow_jobs(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
        COMMON_JOB_PARAMETERS,
    )
    expected_nodes = {
        (
            'projects/project123/subscriptions/sub123',
            'job1',
            'projects/project123/topic/topic123',
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (o:GCPPubsubSubscription)<-[:REFERENCES]-(n:GCPDataFlowJob)-[:REFERENCES]->(m:GCPPubsubTopic) RETURN o.id,n.id,m.id;
        """,
    )

    actual_nodes = {(n['o.id'], n['n.id'], n['m.id']) for n in nodes}

    assert actual_nodes == expected_nodes


def test_dataflow_job_spanner_relation(neo4j_session):
    _seed_org(neo4j_session)
    data = tests.data.gcp.spanner.TEST_INSTANCE_DATABASE
    cartography.intel.gcp.spanner.load_spanner_instances_databases(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
    )
    data = tests.data.gcp.dataflow.TEST_DATAFLOW_JOBS
    cartography.intel.gcp.dataflow.load_dataflow_jobs(
        neo4j_session,
        data,
        TEST_PROJECT_ID,
        TEST_UPDATE_TAG,
        COMMON_JOB_PARAMETERS,
    )
    expected_nodes = {
        (
            'job1',
            'projects/project-123/instances/instance1/databases/database1',
        ),
        (
            'job1',
            'projects/project-123/instances/instance1/databases/database2',
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (n:GCPDataFlowJob)-[:REFERENCES]->(m:GCPSpannerInstanceDatabase) RETURN n.id,m.id;
        """,
    )

    actual_nodes = {(n['n.id'], n['m.id']) for n in nodes}

    assert actual_nodes == expected_nodes
