import cartography.intel.gcp.storage
from cartography.intel.gcp import label
from tests.data.gcp.storage import STORAGE_RESPONSE

TEST_PROJECT_ID = 'project-123'


def test_transform_gcp_buckets():
    bucket_list = cartography.intel.gcp.storage.transform_gcp_buckets(
        STORAGE_RESPONSE['items'], TEST_PROJECT_ID, [],
    )
    assert len(bucket_list) == 1
    bucket = bucket_list[0]
    assert bucket['etag'] == 'CAE='
    assert bucket['project_number'] == 9999
    assert bucket['id'] == 'projects/project-123/locations/us/buckets/bucket_name'
    assert bucket['self_link'] == 'https://www.googleapis.com/storage/v1/b/bucket_name'
    assert bucket['retention_period'] is None


def test_transform_gcp_buckets_keeps_labels_dict():
    # labels must stay a dict — label.get_labels_list() discards anything else,
    # which silently dropped every GCS bucket label
    bucket_list = cartography.intel.gcp.storage.transform_gcp_buckets(
        STORAGE_RESPONSE['items'], TEST_PROJECT_ID, [],
    )
    bucket = bucket_list[0]
    assert bucket['labels'] == {
        'label_key_1': 'label_value_1',
        'label_key_2': 'label_value_2',
    }

    labels = label.get_labels_list(bucket_list)
    assert len(labels) == 2
    assert {(lbl['key'], lbl['value']) for lbl in labels} == {
        ('label_key_1', 'label_value_1'),
        ('label_key_2', 'label_value_2'),
    }
    for lbl in labels:
        assert lbl['resource_id'] == bucket['id']
        assert lbl['id'] == f"{bucket['id']}/label/{lbl['key']}"
