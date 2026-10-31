import logging
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cartography.intel.aws import sagemaker

ARN = 'arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/'


def test_get_notebook_instances_list_reads_direct_internet_access():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {
            'NotebookInstances': [
                {'NotebookInstanceName': 'nb-open', 'NotebookInstanceArn': ARN + 'nb-open'},
                {'NotebookInstanceName': 'nb-vpc-only', 'NotebookInstanceArn': ARN + 'nb-vpc-only'},
                {'NotebookInstanceName': 'nb-denied', 'NotebookInstanceArn': ARN + 'nb-denied'},
            ],
        },
    ]
    # Shape of describe_notebook_instance(); list_notebook_instances does not return DirectInternetAccess.
    described = {
        'nb-open': {'NotebookInstanceName': 'nb-open', 'DirectInternetAccess': 'Enabled'},
        'nb-vpc-only': {
            'NotebookInstanceName': 'nb-vpc-only', 'DirectInternetAccess': 'Disabled', 'SubnetId': 'subnet-1',
        },
    }

    def describe(NotebookInstanceName):
        if NotebookInstanceName not in described:
            raise ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'denied'}}, 'DescribeNotebookInstance',
            )
        return described[NotebookInstanceName]

    client.describe_notebook_instance.side_effect = describe
    session = MagicMock()
    session.client.return_value = client

    instances = sagemaker.get_notebook_instances_list(session, 'us-east-1')

    assert {i['NotebookInstanceName']: i['DirectInternetAccess'] for i in instances} == {
        'nb-open': 'Enabled',
        'nb-vpc-only': 'Disabled',
        # Unknown: not flagged.
        'nb-denied': None,
    }


ACCOUNT_ID = '111111111111'
JOB_ARN = 'arn:aws:sagemaker:us-east-1:111111111111:training-job/'


def _job(name):
    return {'TrainingJobName': name, 'TrainingJobArn': JOB_ARN + name}


def _session(paginate):
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = paginate
    session = MagicMock()
    session.client.return_value = client
    return session, client


def test_get_training_jobs_list_asks_for_running_jobs_and_the_recent_window_only():
    def paginate(**params):
        if params.get('StatusEquals') == 'InProgress':
            return [{'TrainingJobSummaries': [_job('running-for-months'), _job('running-today')]}]
        if params.get('StatusEquals') == 'Stopping':
            return [{'TrainingJobSummaries': []}]
        return [{'TrainingJobSummaries': [_job('running-today'), _job('completed-yesterday')]}]

    session, client = _session(paginate)
    before = datetime.now(timezone.utc)

    jobs = sagemaker.get_training_jobs_list(session, ACCOUNT_ID, 'us-east-1')

    client.get_paginator.assert_called_with('list_training_jobs')
    calls = [c.kwargs for c in client.get_paginator.return_value.paginate.call_args_list]
    newest_first = {'SortBy': 'CreationTime', 'SortOrder': 'Descending', 'PaginationConfig': {'PageSize': 100}}
    assert calls[:2] == [{'StatusEquals': 'InProgress', **newest_first}, {'StatusEquals': 'Stopping', **newest_first}]
    window = calls[2].pop('CreationTimeAfter')
    assert calls[2] == newest_first
    expected_start = before - timedelta(days=sagemaker.TRAINING_JOB_WINDOW_DAYS)
    assert abs((window - expected_start).total_seconds()) < 60
    # A running job older than the window is kept; one returned by two queries is kept once.
    assert [j['TrainingJobName'] for j in jobs] == ['running-for-months', 'running-today', 'completed-yesterday']


def test_get_training_jobs_list_stops_paging_at_the_cap_and_warns(caplog):
    pages_read = []

    def pages():
        while True:
            pages_read.append(1)
            yield {'TrainingJobSummaries': [_job(f'job-{len(pages_read)}-{i}') for i in range(100)]}

    def paginate(**params):
        return pages() if 'CreationTimeAfter' in params else [{'TrainingJobSummaries': []}]

    session, _ = _session(paginate)

    with caplog.at_level(logging.WARNING):
        jobs = sagemaker.get_training_jobs_list(session, ACCOUNT_ID, 'us-east-1')

    cap = sagemaker.MAX_TRAINING_JOBS_PER_REGION
    assert len(jobs) == cap
    # Newest first, so the cap keeps the most recent jobs; one page past the cap proves there are more.
    assert jobs[0]['TrainingJobName'] == 'job-1-0'
    assert len(pages_read) == cap // 100 + 1
    warning = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warning) == 1 and ACCOUNT_ID in warning[0] and 'us-east-1' in warning[0]


MODEL_ARN = 'arn:aws:sagemaker:us-east-1:111111111111:model/'


def test_get_models_list_is_newest_first_without_a_time_filter_and_capped(caplog):
    pages_read = []

    def pages():
        while True:
            pages_read.append(1)
            names = [f'model-{len(pages_read)}-{i}' for i in range(100)]
            yield {'Models': [{'ModelName': n, 'ModelArn': f'{MODEL_ARN}{n}'} for n in names]}

    session, client = _session(lambda **params: pages())

    with caplog.at_level(logging.WARNING):
        models = sagemaker.get_models_list(session, ACCOUNT_ID, 'us-east-1')

    client.get_paginator.assert_called_once_with('list_models')
    # No CreationTimeAfter: an old model can still back a live endpoint.
    client.get_paginator.return_value.paginate.assert_called_once_with(
        SortBy='CreationTime', SortOrder='Descending', PaginationConfig={'PageSize': 100},
    )
    cap = sagemaker.MAX_MODELS_PER_REGION
    assert len(models) == cap
    assert models[0]['ModelName'] == 'model-1-0'
    assert len(pages_read) == cap // 100 + 1
    warning = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warning) == 1 and ACCOUNT_ID in warning[0] and 'us-east-1' in warning[0]
