from cartography.intel.gcp.dataflow import filter_active_dataflow_jobs


def test_filter_active_dataflow_jobs_drops_terminal_states():
    jobs = [
        {'id': 'running', 'currentState': 'JOB_STATE_RUNNING'},
        {'id': 'pending', 'currentState': 'JOB_STATE_PENDING'},
        {'id': 'done', 'currentState': 'JOB_STATE_DONE'},
        {'id': 'failed', 'currentState': 'JOB_STATE_FAILED'},
        {'id': 'cancelled', 'currentState': 'JOB_STATE_CANCELLED'},
        {'id': 'drained', 'currentState': 'JOB_STATE_DRAINED'},
        {'id': 'missing'},
    ]
    filtered = filter_active_dataflow_jobs(jobs)
    assert [j['id'] for j in filtered] == ['running', 'pending', 'missing']


def test_filter_active_dataflow_jobs_empty():
    assert filter_active_dataflow_jobs([]) == []
