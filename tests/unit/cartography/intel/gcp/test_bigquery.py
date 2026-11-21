import json
from unittest.mock import MagicMock

import pytest
from googleapiclient.errors import HttpError

import cartography.intel.gcp.bigquery
import cartography.util


TEST_PROJECT_ID = 'test-project'
TEST_DATASET_ID = 'test_dataset'


def test_transform_dataset_accesses_role_based_entries():
    """Role-based access entries should be transformed with a generated ID."""
    response_objects = [
        {'role': 'WRITER', 'specialGroup': 'allAuthenticatedUsers'},
        {'role': 'READER', 'userByEmail': 'user@example.com'},
    ]

    result = cartography.intel.gcp.bigquery.transform_dataset_accesses(
        response_objects, TEST_DATASET_ID, TEST_PROJECT_ID,
    )

    assert len(result) == 2
    assert result[0]['id'] == (
        f"projects/{TEST_PROJECT_ID}/bigquery/{TEST_DATASET_ID}/role/WRITER/specialGroup/allAuthenticatedUsers"
    )
    assert result[0]['role'] == 'WRITER'
    assert result[0]['specialGroup'] == 'allAuthenticatedUsers'
    assert result[1]['id'] == (
        f"projects/{TEST_PROJECT_ID}/bigquery/{TEST_DATASET_ID}/role/READER/userByEmail/user@example.com"
    )
    assert result[1]['role'] == 'READER'


def test_transform_dataset_accesses_skips_view_entries():
    """View-based access entries (no 'role' key) should be skipped without raising KeyError."""
    response_objects = [
        {'role': 'OWNER', 'userByEmail': 'admin@example.com'},
        {'view': {'datasetId': 'reporting_test', 'projectId': 'other-project', 'tableId': 'view1'}},
        {'role': 'READER', 'specialGroup': 'projectReaders'},
    ]

    result = cartography.intel.gcp.bigquery.transform_dataset_accesses(
        response_objects, TEST_DATASET_ID, TEST_PROJECT_ID,
    )

    assert len(result) == 2
    assert result[0]['id'] == (
        f"projects/{TEST_PROJECT_ID}/bigquery/{TEST_DATASET_ID}/role/OWNER/userByEmail/admin@example.com"
    )
    assert result[1]['id'] == (
        f"projects/{TEST_PROJECT_ID}/bigquery/{TEST_DATASET_ID}/role/READER/specialGroup/projectReaders"
    )


def test_transform_dataset_accesses_skips_routine_entries():
    """Routine-based access entries (no 'role' key) should be skipped."""
    response_objects = [
        {'routine': {'datasetId': 'analytics', 'projectId': 'other-project', 'routineId': 'my_routine'}},
    ]

    result = cartography.intel.gcp.bigquery.transform_dataset_accesses(
        response_objects, TEST_DATASET_ID, TEST_PROJECT_ID,
    )

    assert len(result) == 0


def test_transform_dataset_accesses_skips_dataset_entries():
    """Dataset-based access entries (no 'role' key) should be skipped."""
    response_objects = [
        {'dataset': {'dataset': {'datasetId': 'shared_ds', 'projectId': 'other-project'}, 'targetTypes': ['VIEWS']}},
        {'role': 'WRITER', 'userByEmail': 'writer@example.com'},
    ]

    result = cartography.intel.gcp.bigquery.transform_dataset_accesses(
        response_objects, TEST_DATASET_ID, TEST_PROJECT_ID,
    )

    assert len(result) == 1
    assert result[0]['role'] == 'WRITER'


def test_transform_dataset_accesses_empty_list():
    """Empty input should return empty output."""
    result = cartography.intel.gcp.bigquery.transform_dataset_accesses(
        [], TEST_DATASET_ID, TEST_PROJECT_ID,
    )

    assert result == []


def test_transform_dataset_accesses_all_view_entries():
    """If all entries are views/routines/datasets, result should be empty."""
    response_objects = [
        {'view': {'datasetId': 'ds1', 'projectId': 'p1', 'tableId': 'v1'}},
        {'view': {'datasetId': 'ds2', 'projectId': 'p2', 'tableId': 'v2'}},
        {'routine': {'datasetId': 'ds3', 'projectId': 'p3', 'routineId': 'r1'}},
    ]

    result = cartography.intel.gcp.bigquery.transform_dataset_accesses(
        response_objects, TEST_DATASET_ID, TEST_PROJECT_ID,
    )

    assert result == []


def test_transform_dataset_accesses_keeps_one_entry_per_member_of_a_role():
    """Several members on the same role used to share one id, so the last one overwrote the others."""
    result = cartography.intel.gcp.bigquery.transform_dataset_accesses(
        [
            {'role': 'READER', 'userByEmail': 'user@example.com'},
            {'role': 'READER', 'iamMember': 'allUsers'},
            {'role': 'READER', 'specialGroup': 'projectReaders'},
        ],
        TEST_DATASET_ID, TEST_PROJECT_ID,
    )

    assert len({r['id'] for r in result}) == 3
    assert result[1]['id'] == f"projects/{TEST_PROJECT_ID}/bigquery/{TEST_DATASET_ID}/role/READER/iamMember/allUsers"
    assert result[1]['iamMember'] == 'allUsers'


def test_dataset_and_table_ids_are_project_qualified(mocker):
    """datasetId / tableId are unique only inside a project: node ids carry the project, the API gets the short id."""
    module = cartography.intel.gcp.bigquery
    dataset_info = mocker.patch.object(module, 'get_dataset_info', return_value={})
    mocker.patch.object(module.gcp_console_link, 'get_console_link', return_value='link')

    datasets = module.transform_bigquery_dataset(None, [{'datasetReference': {'datasetId': 'billing_export'}}], 'p1')
    tables = module.transform_bigquery_tables(datasets[0], [{'tableReference': {'tableId': 'events'}}], 'p1')

    assert (datasets[0]['id'], datasets[0]['uniqueId'], datasets[0]['name']) == (
        'projects/p1/datasets/billing_export', 'projects/p1/datasets/billing_export', 'billing_export',
    )
    assert (tables[0]['id'], tables[0]['datasetId'], tables[0]['name']) == (
        'projects/p1/datasets/billing_export/tables/events', 'projects/p1/datasets/billing_export', 'events',
    )
    dataset_info.assert_called_once_with(None, 'billing_export', 'p1')


def test_spent_budget_stops_the_sync_before_cleanup(mocker):
    """Past the sync budget the table loop stops and cleanup does not run, so unreached datasets keep their tables."""
    module = cartography.intel.gcp.bigquery
    mocker.patch.object(module, 'get_bigquery_dataset', return_value=_datasets('a', 'b'))
    mocker.patch.object(module, 'get_dataset_info', return_value={'access': []})
    mocker.patch.object(module.gcp_console_link, 'get_console_link', return_value='link')
    for loader in ('load_bigquery_datasets', 'attach_dataset_to_accesses', 'load_bigquery_tables'):
        mocker.patch.object(module, loader)
    mocker.patch.object(module.label, 'sync_labels')
    get_tables = mocker.patch.object(module, 'get_bigquery_tables', return_value=[])
    cleanup = mocker.patch.object(module, 'cleanup_gcp_bigquery')
    calls = []

    def deadline(where):
        # Budget left for the dataset pass, spent after the first dataset's tables.
        calls.append(where)
        if where.startswith('bigquery tables') and len([c for c in calls if 'tables' in c]) > 1:
            raise cartography.util.SyncDeadlineExceeded(where)

    mocker.patch.object(module, 'check_sync_deadline', side_effect=deadline)

    with pytest.raises(cartography.util.SyncDeadlineExceeded):
        module.sync(MagicMock(), None, 'p1', 1, {'service_labels': []}, [])

    assert get_tables.call_count == 1
    cleanup.assert_not_called()


def _datasets(*names):
    return [{'datasetReference': {'datasetId': n}} for n in names]


def test_one_datasets_get_serves_details_and_access(mocker):
    """datasets.get used to be made twice per dataset (details, then access): 3,000 calls for 1,500 datasets."""
    module = cartography.intel.gcp.bigquery
    mocker.patch.object(module.gcp_console_link, 'get_console_link', return_value='link')
    bigquery = MagicMock()
    bigquery.datasets().get().execute.side_effect = [
        {'location': 'US', 'access': [{'role': 'READER', 'iamMember': 'allUsers'}]},
        {'location': 'EU'},
    ]
    bigquery.datasets().get.reset_mock()

    datasets = module.transform_bigquery_dataset(bigquery, _datasets('a', 'b'), 'p1')

    assert bigquery.datasets().get.call_count == 2
    assert [d['details']['location'] for d in datasets] == ['US', 'EU']
    assert [d['accesses'] for d in datasets] == [[{'role': 'READER', 'iamMember': 'allUsers'}], []]


def test_unreadable_dataset_has_no_details_and_unknown_access(mocker):
    """A permission-denied datasets.get leaves accesses None (IAM policy unresolved), not [] (no access)."""
    module = cartography.intel.gcp.bigquery
    mocker.patch.object(module.gcp_console_link, 'get_console_link', return_value='link')
    bigquery = MagicMock()
    denied = {'code': 403, 'message': 'Access Denied', 'status': 'PERMISSION_DENIED'}
    bigquery.datasets().get().execute.side_effect = HttpError(
        resp=MagicMock(status=403), content=json.dumps({'error': denied}).encode(),
    )

    datasets = module.transform_bigquery_dataset(bigquery, _datasets('locked'), 'p1')

    assert (datasets[0]['details'], datasets[0]['accesses']) == ({}, None)
    assert not hasattr(module, 'get_dataset_access_info')


def test_tables_are_built_from_the_list_response_alone(mocker):
    """Log-sink datasets hold thousands of daily tables: no per-table tables.get (cloudanix-web #5338)."""
    module = cartography.intel.gcp.bigquery
    mocker.patch.object(module.gcp_console_link, 'get_console_link', return_value='link')
    dataset = {'id': 'projects/p1/datasets/logs', 'name': 'logs'}
    rows = [
        {
            'tableReference': {'tableId': f'requests_202611{day:02d}'},
            'friendlyName': f'requests {day}',
            'requirePartitionFilter': day % 2 == 0,
        }
        for day in range(1, 31)
    ]

    tables = module.transform_bigquery_tables(dataset, rows, 'p1')

    assert not hasattr(module, 'get_table_info')
    assert len(tables) == 30
    assert (tables[1]['name'], tables[1]['friendlyName'], tables[1]['requirePartitionFilter']) == (
        'requests_20261102', 'requests 2', True,
    )
    assert 'details' not in tables[0]
