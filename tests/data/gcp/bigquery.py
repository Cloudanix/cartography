# Ids as transform_bigquery_dataset / transform_bigquery_tables build them for project 000000000000.
DATASET_PREFIX = 'projects/000000000000/datasets'

TEST_DATASET = [
    {
        'id': f'{DATASET_PREFIX}/dataset1',
        'name': 'dataset1',
        'details': {
            'friendlyName': 'dataset123',
            'defaultTableExpirationMs': '23',
            'defaultPartitionExpirationMs': '20',
            'location': 'us-east1',
            'defaultCollation': 'und:ci',
            'maxTimeTravelHours': '2',
        },
    },
    {
        'id': f'{DATASET_PREFIX}/dataset2',
        'name': 'dataset2',
        'details': {
            'friendlyName': 'dataset1234',
            'defaultTableExpirationMs': '25',
            'defaultPartitionExpirationMs': '26',
            'location': 'us-east1',
            'defaultCollation': 'und:ci',
            'maxTimeTravelHours': '2',
        },
    },
]

TEST_TABLE = [
    {
        'id': f'{DATASET_PREFIX}/dataset1/tables/table1',
        'name': 'table1',
        'datasetId': f'{DATASET_PREFIX}/dataset1',
        'details': {
            'friendlyName': 'table123',
            'requirePartitionFilter': True,
            'numBytes': '34',
            'numLongTermBytes': '128',
            'numRows': '4',
        },
    },
    {
        'id': f'{DATASET_PREFIX}/dataset2/tables/table2',
        'name': 'table2',
        'datasetId': f'{DATASET_PREFIX}/dataset2',
        'details': {
            'friendlyName': 'table1234',
            'requirePartitionFilter': True,
            'numBytes': '35',
            'numLongTermBytes': '256',
            'numRows': '3',
        },
    },
]

TEST_ACCESSES = [
    {
        'id': "projects/000000000000/bigquery/dataset1/role/WRITER",
        'specialGroup': 'allAuthenticatedUsers',
        'role': 'WRITER',
    },
]
