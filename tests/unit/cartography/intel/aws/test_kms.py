from cartography.intel.aws.kms import filter_live_kms_keys


def test_filter_live_kms_keys_skips_pending_deletion():
    keys = [
        {'KeyId': 'k-enabled', 'KeyState': 'Enabled'},
        {'KeyId': 'k-disabled', 'KeyState': 'Disabled'},
        {'KeyId': 'k-pending', 'KeyState': 'PendingDeletion'},
        {'KeyId': 'k-missing'},
    ]
    filtered = filter_live_kms_keys(keys)
    assert [k['KeyId'] for k in filtered] == ['k-enabled', 'k-disabled', 'k-missing']


def test_filter_live_kms_keys_empty():
    assert filter_live_kms_keys([]) == []
