from cartography.intel.gcp.dataflow import DATAFLOW_ACTIVE_FILTER


def test_dataflow_active_filter_is_api_enum():
    assert DATAFLOW_ACTIVE_FILTER == 'ACTIVE'
