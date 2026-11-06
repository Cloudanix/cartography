import logging
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from unittest.mock import MagicMock

from cartography.intel.aws import bedrock

ACCOUNT_ID = '111111111111'
JOB_ARN = 'arn:aws:bedrock:us-east-1:111111111111:model-customization-job/'


def _job(name):
    return {'jobName': name, 'jobArn': JOB_ARN + name}


def _session(paginate):
    client = MagicMock()
    client.get_paginator.return_value.paginate.side_effect = paginate
    session = MagicMock()
    session.client.return_value = client
    return session, client


def test_get_model_customisation_jobs_list_asks_for_running_jobs_and_the_window_only():
    def paginate(**params):
        if params.get('statusEquals') == 'InProgress':
            return [{'modelCustomizationJobSummaries': [_job('running-for-years'), _job('running-today')]}]
        if params.get('statusEquals') == 'Stopping':
            return [{'modelCustomizationJobSummaries': []}]
        return [{'modelCustomizationJobSummaries': [_job('running-today'), _job('completed-last-month')]}]

    session, client = _session(paginate)
    before = datetime.now(timezone.utc)

    jobs = bedrock.get_model_customisation_jobs_list(session, ACCOUNT_ID, 'us-east-1')

    client.get_paginator.assert_called_with('list_model_customization_jobs')
    calls = [c.kwargs for c in client.get_paginator.return_value.paginate.call_args_list]
    newest_first = {'sortBy': 'CreationTime', 'sortOrder': 'Descending', 'PaginationConfig': {'PageSize': 1000}}
    assert calls[:2] == [{'statusEquals': 'InProgress', **newest_first}, {'statusEquals': 'Stopping', **newest_first}]
    window = calls[2].pop('creationTimeAfter')
    assert calls[2] == newest_first
    expected_start = before - timedelta(days=bedrock.CUSTOMISATION_JOB_WINDOW_DAYS)
    assert abs((window - expected_start).total_seconds()) < 60
    # A running job older than the window is kept; one returned by two queries is kept once.
    assert [j['jobName'] for j in jobs] == ['running-for-years', 'running-today', 'completed-last-month']


def test_get_model_customisation_jobs_list_stops_paging_at_the_cap_and_warns(caplog):
    pages_read = []

    def pages():
        while True:
            pages_read.append(1)
            yield {'modelCustomizationJobSummaries': [_job(f'job-{len(pages_read)}-{i}') for i in range(1000)]}

    def paginate(**params):
        return pages() if 'creationTimeAfter' in params else [{'modelCustomizationJobSummaries': []}]

    session, _ = _session(paginate)

    with caplog.at_level(logging.WARNING):
        jobs = bedrock.get_model_customisation_jobs_list(session, ACCOUNT_ID, 'us-east-1')

    cap = bedrock.MAX_CUSTOMISATION_JOBS_PER_REGION
    assert len(jobs) == cap
    assert jobs[0]['jobName'] == 'job-1-0'
    assert len(pages_read) == cap // 1000 + 1
    warning = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warning) == 1 and ACCOUNT_ID in warning[0] and 'us-east-1' in warning[0]
