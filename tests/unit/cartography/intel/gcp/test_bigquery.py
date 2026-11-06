import cartography.intel.gcp.bigquery


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
    table_info = mocker.patch.object(module, 'get_table_info', return_value={})
    mocker.patch.object(module.gcp_console_link, 'get_console_link', return_value='link')

    datasets = module.transform_bigquery_dataset(None, [{'datasetReference': {'datasetId': 'billing_export'}}], 'p1')
    tables = module.transform_bigquery_tables(None, datasets[0], [{'tableReference': {'tableId': 'events'}}], 'p1')

    assert (datasets[0]['id'], datasets[0]['uniqueId'], datasets[0]['name']) == (
        'projects/p1/datasets/billing_export', 'projects/p1/datasets/billing_export', 'billing_export',
    )
    assert (tables[0]['id'], tables[0]['datasetId'], tables[0]['name']) == (
        'projects/p1/datasets/billing_export/tables/events', 'projects/p1/datasets/billing_export', 'events',
    )
    dataset_info.assert_called_once_with(None, 'billing_export', 'p1')
    table_info.assert_called_once_with(None, 'p1', 'billing_export', 'events')
