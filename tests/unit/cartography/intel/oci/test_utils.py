from datetime import datetime
from datetime import timezone
from unittest.mock import MagicMock

import oci
import pytest

from cartography.intel.oci import utils

OCI_OBJECT = """[{
        "capabilities": {
            "can_use_api_keys": true,
            "can_use_auth_tokens": true
        },
        "compartment_id": "ocid1.tenancy.oc1..123"
}]"""

JSON_OCI_OBJECT = {
    "capabilities": {
        "can_use_api_keys": True,
        "can_use_auth_tokens": True,
    },
    "compartment_id": "ocid1.tenancy.oc1..123",
}


def test_oci_object_to_json():
    json_out = utils.oci_object_to_json(OCI_OBJECT)
    assert isinstance(json_out, list)
    assert isinstance(json_out[0]["capabilities"], dict)
    assert isinstance(json_out[0]["compartment-id"], str)
    assert json_out[0]["compartment-id"] == "ocid1.tenancy.oc1..123"


def test_replace_char_in_dict():
    adjusted_dict = utils.replace_char_in_dict(JSON_OCI_OBJECT)
    assert isinstance(adjusted_dict, dict)
    assert "compartment-id" in adjusted_dict.keys()


def test_get_console_link():
    assert utils.get_console_link("compute_instance", region="us-phoenix-1", ocid="ocid1.instance.oc1..a") == (
        "https://cloud.oracle.com/compute/instances/ocid1.instance.oc1..a?region=us-phoenix-1"
    )


def test_get_console_link_missing_identifiers_returns_none():
    # A missing region/ocid must not raise out of a sync.
    assert utils.get_console_link("compute_instance", region="", ocid="ocid1.instance.oc1..a") is None
    assert utils.get_console_link("compute_instance", region="us-phoenix-1", ocid=None) is None


def _real_sdk_client():
    return oci.monitoring.MonitoringClient(
        {"region": "us-phoenix-1"}, signer=MagicMock(spec=oci.auth.signers.SecurityTokenSigner),
    )


def test_sdk_reads_a_date_after_year_9999_as_datetime_max():
    # Without the patch the SDK raises "Failed to parse ... into a datetime object" and
    # the whole list call fails. Seen on PAR timeExpires; alarm suppression is the same shape.
    body = b'[{"id": "a1", "suppression": {"timeSuppressFrom": "2026-01-01T00:00:00.000Z",' \
        b' "timeSuppressUntil": "+20000-01-01T00:00:00.000Z"}}]'

    alarms = _real_sdk_client().base_client.deserialize_response_data(body, "list[AlarmSummary]")

    assert alarms[0].suppression.time_suppress_until == datetime.max.replace(tzinfo=timezone.utc)
    assert alarms[0].suppression.time_suppress_from == datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_sdk_still_rejects_an_unparseable_date():
    body = b'[{"id": "a1", "suppression": {"timeSuppressUntil": "not-a-date"}}]'

    with pytest.raises(Exception, match="into a datetime object"):
        _real_sdk_client().base_client.deserialize_response_data(body, "list[AlarmSummary]")
