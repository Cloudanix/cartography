from cartography.intel.oci.compute import filter_active_oci_instances


def test_filter_active_oci_instances_keeps_live_states():
    instances = [
        {'id': 'i-running', 'lifecycle-state': 'RUNNING'},
        {'id': 'i-stopped', 'lifecycle-state': 'STOPPED'},
        {'id': 'i-starting', 'lifecycle-state': 'STARTING'},
        {'id': 'i-terminated', 'lifecycle-state': 'TERMINATED'},
        {'id': 'i-terminating', 'lifecycle-state': 'TERMINATING'},
        {'id': 'i-creating', 'lifecycle-state': 'CREATING'},
        {'id': 'i-missing'},
    ]
    filtered = filter_active_oci_instances(instances)
    assert [i['id'] for i in filtered] == ['i-running', 'i-stopped', 'i-starting']


def test_filter_active_oci_instances_empty():
    assert filter_active_oci_instances([]) == []
