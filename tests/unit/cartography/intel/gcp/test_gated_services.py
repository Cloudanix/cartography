from cartography.intel.gcp import _GATEABLE_SERVICE_APIS
from cartography.intel.gcp import _gated_out_services

REQUESTED = [
    "compute",
    "cloudcdn",
    "loadbalancer",
    "bigquery",
    "gke",
    "iam",
    "admin",
    "artifacts",
]


def test_empty_enabled_set_disables_the_gate():
    # A failed/empty ServiceUsage lookup must never gate anything - else a single transient error would silently
    # drop an entire project's resources.
    assert _gated_out_services(REQUESTED, set()) == set()


def test_disabled_api_is_gated_enabled_is_not():
    enabled = {"compute.googleapis.com", "container.googleapis.com"}
    out = _gated_out_services(REQUESTED, enabled)
    assert "bigquery" in out  # bigquery.googleapis.com absent -> skipped
    assert {"compute", "cloudcdn", "loadbalancer"}.isdisjoint(out)  # compute.googleapis.com present
    assert "gke" not in out  # container.googleapis.com present


def test_unmapped_services_are_never_gated():
    # iam (multi-API), admin (workspace, org-scoped), artifacts (ambiguous) are intentionally absent from the map.
    out = _gated_out_services(REQUESTED, {"compute.googleapis.com"})
    assert {"iam", "admin", "artifacts"}.isdisjoint(out)


def test_compute_family_gated_together_when_compute_disabled():
    out = _gated_out_services(REQUESTED, {"bigquery.googleapis.com"})
    assert {"compute", "cloudcdn", "loadbalancer", "gke"} <= out
    assert "bigquery" not in out


def test_map_values_are_canonical_service_names():
    # Guard against a malformed entry sneaking in (every value must look like a ServiceUsage config.name).
    for func, api in _GATEABLE_SERVICE_APIS.items():
        assert api.endswith(".googleapis.com"), f"{func} -> {api} is not a canonical service name"
