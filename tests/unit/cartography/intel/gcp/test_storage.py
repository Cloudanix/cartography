from unittest.mock import MagicMock

from googleapiclient.errors import HttpError

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


def _bucket(**fields):
    return dict({'name': 'b', 'location': 'US', 'projectNumber': 1}, **fields)


def test_transform_gcp_buckets_keeps_public_access_prevention_and_public_acl_entities():
    buckets = cartography.intel.gcp.storage.transform_gcp_buckets(
        [
            _bucket(
                iamConfiguration={'publicAccessPrevention': 'enforced', 'uniformBucketLevelAccess': {'enabled': False}},
                acl=[{'entity': 'allUsers', 'role': 'READER'}, {'entity': 'project-owners-1', 'role': 'OWNER'}],
                defaultObjectAcl=[{'entity': 'allAuthenticatedUsers', 'role': 'READER'}],
            ),
            _bucket(name='private'),
        ], TEST_PROJECT_ID, [],
    )
    assert buckets[0]['public_access_prevention'] == 'enforced'
    assert buckets[0]['public_acl_entities'] == ['allAuthenticatedUsers', 'allUsers']
    assert buckets[1]['public_access_prevention'] is None
    assert buckets[1]['public_acl_entities'] == []


def test_get_gcp_buckets_asks_for_acls_and_falls_back_without_them():
    storage = MagicMock()
    storage.buckets.return_value.list_next.return_value = None
    storage.buckets.return_value.list.return_value.execute.return_value = {'items': [_bucket()]}
    assert cartography.intel.gcp.storage.get_gcp_buckets(storage, TEST_PROJECT_ID, {}) == [_bucket()]
    storage.buckets.return_value.list.assert_called_once_with(project=TEST_PROJECT_ID, projection='full')

    # Without permission for the full projection, list the buckets without ACLs rather than none at all.
    forbidden = HttpError(MagicMock(status=403), b'{"error": {"errors": [{"reason": "forbidden"}]}}')
    storage.buckets.return_value.list.reset_mock()
    storage.buckets.return_value.list.return_value.execute.side_effect = [forbidden, {'items': [_bucket()]}]
    assert cartography.intel.gcp.storage.get_gcp_buckets(storage, TEST_PROJECT_ID, {}) == [_bucket()]
    assert [c.kwargs for c in storage.buckets.return_value.list.call_args_list] == [
        {'project': TEST_PROJECT_ID, 'projection': 'full'}, {'project': TEST_PROJECT_ID, 'projection': 'noAcl'},
    ]
