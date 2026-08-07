from cartography.intel.gcp.dataproc import DATAPROC_LIST_STATE_FILTERS


def test_dataproc_list_state_filters_are_api_status_filters():
    assert 'status.state = ACTIVE' in DATAPROC_LIST_STATE_FILTERS
    assert 'status.state = STOPPED' in DATAPROC_LIST_STATE_FILTERS
    assert 'status.state = STOPPING' in DATAPROC_LIST_STATE_FILTERS
    assert not any('TERMINATED' in f for f in DATAPROC_LIST_STATE_FILTERS)
