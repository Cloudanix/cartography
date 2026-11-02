from cartography.intel.gcp import dataflow

TEST_UPDATE_TAG = 123456789


def _params(tenant):
    return {'WORKSPACE_ID': f'ws-dft-{tenant}', 'GCP_ORGANIZATION_ID': f'org-dft-{tenant}'}


def _project(tenant):
    return f'proj-dft-{tenant}'


def _targets(project):
    return {
        'bigtable': f'projects/{project}/instances/bt/tables/t',
        'bigquery': f'projects/{project}/datasets/d/tables/t',
        'topic': f'projects/{project}/topics/tp',
        'subscription': f'projects/{project}/subscriptions/sub',
        'spanner': f'projects/{project}/instances/sp/databases/db',
    }


def _seed(neo4j_session, tenant):
    # Each customer's project holds one target of every kind a job can reference.
    project = _project(tenant)
    t = _targets(project)
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:GCPOrganization{id: $org})-[:OWNER]->(p:GCPProject{id: $p})
        MERGE (p)-[:RESOURCE]->(:GCPBigtableInstance{id: $p + '/bt'})-[:HAS_TABLE]->(:GCPBigtableTable{id: $bigtable})
        MERGE (p)-[:RESOURCE]->(:GCPBigqueryDataset{id: $p + '/d'})-[:HAS_TABLE]->(:GCPBigqueryTable{id: $bigquery})
        MERGE (p)-[:RESOURCE]->(:GCPPubsubTopic{id: $topic})
        MERGE (p)-[:RESOURCE]->(:GCPPubsubSubscription{id: $subscription})
        MERGE (p)-[:RESOURCE]->(:GCPSpannerInstance{id: $p + '/sp'})
            -[:HAS_DATABASE]->(:GCPSpannerInstanceDatabase{id: $spanner})
        """,
        ws=_params(tenant)['WORKSPACE_ID'], org=_params(tenant)['GCP_ORGANIZATION_ID'], p=project, **t,
    )


def _job(job_id, projects):
    targets = [_targets(p) for p in projects]
    return {
        'id': job_id, 'name': job_id, 'environment': {},
        'bigTables': [t['bigtable'] for t in targets],
        'bigQueries': [t['bigquery'] for t in targets],
        'pubSub': [{'topicId': t['topic'], 'subscriptionId': t['subscription']} for t in targets],
        'spannerDatabases': [t['spanner'] for t in targets],
    }


def _references(neo4j_session, job_id):
    rows = neo4j_session.run("MATCH (:GCPDataFlowJob{id: $id})-[:REFERENCES]->(t) RETURN t.id AS id", id=job_id)
    return {r['id'] for r in rows}


def test_dataflow_job_references_stay_inside_its_org(neo4j_session):
    for tenant in ('a', 'b'):
        _seed(neo4j_session, tenant)
    # Tenant a's job names its own targets and, with the same names, tenant b's.
    job = _job('job-dft', [_project('a'), _project('b')])

    dataflow.load_dataflow_jobs(neo4j_session, [job], _project('a'), TEST_UPDATE_TAG, _params('a'))

    assert _references(neo4j_session, 'job-dft') == set(_targets(_project('a')).values())


def test_dataflow_job_without_some_references_keeps_the_rest_and_its_project(neo4j_session):
    _seed(neo4j_session, 'a')
    # No Bigtable or Pub/Sub use: the BigQuery and Spanner links and the project edge must still be written.
    job = {**_job('job-dft-partial', [_project('a')]), 'bigTables': [], 'pubSub': []}

    dataflow.load_dataflow_jobs(neo4j_session, [job], _project('a'), TEST_UPDATE_TAG, _params('a'))

    t = _targets(_project('a'))
    assert _references(neo4j_session, 'job-dft-partial') == {t['bigquery'], t['spanner']}
    assert neo4j_session.run(
        "MATCH (:GCPProject{id: $p})-[:RESOURCE]->(j:GCPDataFlowJob{id: 'job-dft-partial'}) RETURN count(j) AS c",
        p=_project('a'),
    ).single()['c'] == 1
