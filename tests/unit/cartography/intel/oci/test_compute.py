from cartography.intel.oci.compute import ACTIVE_INSTANCE_LIFECYCLE_STATES


def test_active_instance_lifecycle_states_for_api_filter():
    assert 'RUNNING' in ACTIVE_INSTANCE_LIFECYCLE_STATES
    assert 'STOPPED' in ACTIVE_INSTANCE_LIFECYCLE_STATES
    assert 'TERMINATED' not in ACTIVE_INSTANCE_LIFECYCLE_STATES
    assert 'TERMINATING' not in ACTIVE_INSTANCE_LIFECYCLE_STATES
    assert 'CREATING' not in ACTIVE_INSTANCE_LIFECYCLE_STATES
