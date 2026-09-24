import pytest

from cartography.intel.gcp import _resolve_sync_regions


@pytest.mark.parametrize(
    "all_regions, input_regions, expected",
    [
        (["us-east1", "us-west1"], [], ["us-east1", "us-west1"]),
        # invalid provided regions are dropped
        (["us-east1", "us-west1"], ["us-west1", "mars-1"], ["us-west1"]),
        # region lookup denied/disabled: "unknown", not "none", so keep what the caller asked for
        # (https://cloudanix.sentry.io/issues/CDX-CARTOGRAPHY-INVENTORY-25B)
        ([], ["us-west1"], ["us-west1"]),
        ([], [], []),
    ],
)
def test_resolve_sync_regions(all_regions, input_regions, expected):
    assert _resolve_sync_regions(all_regions, input_regions) == expected
