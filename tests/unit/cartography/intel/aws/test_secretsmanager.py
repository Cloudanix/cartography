import datetime
from datetime import timezone as tz

from cartography.intel.aws.secretsmanager import filter_active_secrets


def test_filter_active_secrets_excludes_deleted():
    secrets = [
        {'Name': 'live'},
        {'Name': 'deleting', 'DeletedDate': datetime.datetime(2024, 1, 1, tzinfo=tz.utc)},
        {'Name': 'also-live', 'DeletedDate': None},
    ]
    filtered = filter_active_secrets(secrets)
    assert [s['Name'] for s in filtered] == ['live', 'also-live']


def test_filter_active_secrets_empty():
    assert filter_active_secrets([]) == []
