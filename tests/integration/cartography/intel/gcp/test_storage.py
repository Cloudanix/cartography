import cartography.intel.gcp.storage
import tests.data.gcp.storage
from cartography.util import run_analysis_job


TEST_UPDATE_TAG = 123456789
TEST_PROJECT_NUMBER = '000000000000'


def _ensure_local_neo4j_has_test_storage_bucket_data(neo4j_session):
    bucket_res = tests.data.gcp.storage.STORAGE_RESPONSE
    bucket_list = cartography.intel.gcp.storage.transform_gcp_buckets(bucket_res.get('items', []), TEST_PROJECT_NUMBER, regions=None)
    cartography.intel.gcp.storage.load_gcp_buckets(neo4j_session, bucket_list, TEST_PROJECT_NUMBER, TEST_UPDATE_TAG)


def test_transform_and_load_storage_buckets(neo4j_session):
    """
    Test that we can correctly transform and load GCP Storage Buckets to Neo4j.
    """
    _ensure_local_neo4j_has_test_storage_bucket_data(neo4j_session)
    query = """
    MATCH(bucket:GCPBucket{id:$BucketId})
    RETURN bucket.id, bucket.project_number, bucket.kind
    """
    expected_id = 'projects/000000000000/locations/us/buckets/bucket_name'
    expected_project_num = 9999
    expected_kind = 'storage#bucket'
    nodes = neo4j_session.run(
        query,
        BucketId=expected_id,
    )
    actual_nodes = {(n['bucket.id'], n['bucket.project_number'], n['bucket.kind']) for n in nodes}
    expected_nodes = {
        (expected_id, expected_project_num, expected_kind),
    }

    assert actual_nodes == expected_nodes


def test_attach_storage_bucket_labels(neo4j_session):
    """
    Test that we can attach GCP storage bucket labels
    """
    _ensure_local_neo4j_has_test_storage_bucket_data(neo4j_session)
    query = """
    MATCH(bucket:GCPBucket{id:$BucketId})-[r:LABELED]->(label:GCPBucketLabel)
    RETURN bucket.id, label.key, label.value
    ORDER BY label.key
    LIMIT 1
    """
    expected_id = 'projects/000000000000/locations/us/buckets/bucket_name'
    expected_label_key = 'label_key_1'
    expected_label_value = 'label_value_1'
    nodes = neo4j_session.run(
        query,
        BucketId=expected_id,
    )
    actual_nodes = {(n['bucket.id'], n['label.key'], n['label.value']) for n in nodes}
    expected_nodes = {
        (expected_id, expected_label_key, expected_label_value),
    }
    assert actual_nodes == expected_nodes


BUCKET_PARAMS = {
    'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': 'ws-buckets', 'GCP_ORGANIZATION_ID': 'org-buckets',
    'GCP_PROJECT_ID': 'proj-buckets', 'LIMIT_SIZE': 1000,
}


def test_bucket_exposure_honours_public_access_prevention_and_legacy_acls(neo4j_session):
    project = BUCKET_PARAMS['GCP_PROJECT_ID']
    neo4j_session.run(
        "MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(:GCPOrganization{id: $org})-[:OWNER]->(:GCPProject{id: $p})",
        ws=BUCKET_PARAMS['WORKSPACE_ID'], org=BUCKET_PARAMS['GCP_ORGANIZATION_ID'], p=project,
    )

    def bucket(name, pap='inherited', uniform=False, acl=(), default_acl=()):
        return {
            'name': name, 'location': 'US', 'projectNumber': 1,
            'iamConfiguration': {'publicAccessPrevention': pap, 'uniformBucketLevelAccess': {'enabled': uniform}},
            'acl': [{'entity': e} for e in acl], 'defaultObjectAcl': [{'entity': e} for e in default_acl],
        }
    raw = [
        bucket('iam-public'),
        bucket('iam-public-pap-enforced', pap='enforced'),
        bucket('acl-public', acl=['allUsers', 'project-owners-1']),
        bucket('default-acl-public', default_acl=['allAuthenticatedUsers']),
        bucket('acl-public-uniform', uniform=True, acl=['allUsers']),
        bucket('acl-public-pap-enforced', pap='enforced', acl=['allUsers']),
        bucket('private', acl=['project-owners-1']),
    ]
    buckets = cartography.intel.gcp.storage.transform_gcp_buckets(raw, project, [])
    cartography.intel.gcp.storage.load_gcp_buckets(neo4j_session, buckets, project, TEST_UPDATE_TAG)
    for b in buckets:
        if b['name'].startswith('iam-public'):
            bindings = cartography.intel.gcp.storage.transform_gcp_bucket_iam_policy_bindings(
                [{'role': 'roles/storage.objectViewer', 'members': ['allUsers']}], project, b['id'],
            )
            cartography.intel.gcp.storage.load_bucket_iam_policy_bindings(
                neo4j_session, bindings, b['id'], TEST_UPDATE_TAG,
            )

    run_analysis_job('gcp_storage_bucket_policy_analysis.json', neo4j_session, BUCKET_PARAMS)

    rows = neo4j_session.run(
        "MATCH (:GCPProject{id: $p})-[:RESOURCE]->(b:GCPBucket) WHERE b.exposed_internet "
        "RETURN b.name AS name, b.exposed_internet_type AS types",
        p=project,
    )
    assert {r['name']: r['types'] for r in rows} == {
        'iam-public': ['allUsers'],
        'acl-public': ['allUsers'],
        'default-acl-public': ['allAuthenticatedUsers'],
    }
