from cartography.intel.gcp.dataproc import filter_active_dataproc_clusters


def test_filter_active_dataproc_clusters_drops_terminated():
    clusters = [
        {'clusterName': 'live', 'status': {'state': 'RUNNING'}},
        {'clusterName': 'creating', 'status': {'state': 'CREATING'}},
        {'clusterName': 'start', 'status': {'state': 'START'}},
        {'clusterName': 'terminated', 'status': {'state': 'TERMINATED'}},
        {'clusterName': 'error', 'status': {'state': 'ERROR'}},
        {'clusterName': 'deleting', 'status': {'state': 'DELETING'}},
        {'clusterName': 'missing-status'},
    ]
    filtered = filter_active_dataproc_clusters(clusters)
    assert [c['clusterName'] for c in filtered] == ['live', 'creating', 'start', 'missing-status']


def test_filter_active_dataproc_clusters_empty():
    assert filter_active_dataproc_clusters([]) == []
