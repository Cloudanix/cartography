"""Secrets Manager filters at the API via IncludePlannedDeletion=False."""
import inspect

from cartography.intel.aws import secretsmanager


def test_get_secret_list_source_passes_include_planned_deletion_false():
    source = inspect.getsource(secretsmanager.get_secret_list)
    assert 'IncludePlannedDeletion=False' in source
    assert 'filter_active_secrets' not in source
