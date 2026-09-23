import logging
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

import cartography.intel.aws
from cartography.intel.aws import ec2
from cartography.util import is_aws_access_denied

SCP_MESSAGE = (
    "You are not authorized to perform this operation. User: arn:aws:sts::123:assumed-role/x "
    "is not authorized to perform: ec2:DescribeRegions with an explicit deny in a service control policy"
)


def _client_error(code: str, message: str = "denied") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "DescribeRegions")


def _session_raising(error: Exception) -> MagicMock:
    session = MagicMock()
    session.client.return_value.describe_regions.side_effect = error
    return session


@pytest.mark.parametrize(
    "error",
    [
        _client_error("UnauthorizedOperation"),
        _client_error("AccessDenied"),
        _client_error("AuthFailure"),
        _client_error("OptInRequired"),
        _client_error("SomeNewCode", SCP_MESSAGE),
    ],
)
def test_is_aws_access_denied_true(error):
    assert is_aws_access_denied(error)


@pytest.mark.parametrize("error", [_client_error("InternalError"), ValueError("boom")])
def test_is_aws_access_denied_false(error):
    assert not is_aws_access_denied(error)


# Regression for https://cloudanix.sentry.io/issues/CDX-AWS-BACKEND-PYTHON-MZ
@pytest.mark.parametrize(
    "discover",
    [
        lambda session: ec2.get_ec2_regions(session, "123"),
        lambda session: cartography.intel.aws.list_all_regions(session, cartography.intel.aws.logger),
    ],
)
def test_region_discovery_denial_not_logged_as_error(discover, caplog):
    session = _session_raising(_client_error("UnauthorizedOperation", SCP_MESSAGE))

    with caplog.at_level(logging.DEBUG):
        assert discover(session) == []

    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize(
    "discover",
    [
        lambda session: ec2.get_ec2_regions(session, "123"),
        lambda session: cartography.intel.aws.list_all_regions(session, cartography.intel.aws.logger),
    ],
)
def test_region_discovery_unexpected_error_still_logged(discover, caplog):
    session = _session_raising(_client_error("InternalError"))

    assert discover(session) == []

    assert [r for r in caplog.records if r.levelno == logging.ERROR]


def test_resolve_sync_regions_uses_provided_regions_without_discovery():
    session = MagicMock()

    assert cartography.intel.aws._resolve_sync_regions(session, "123", ["us-west-2", "eu-west-1"]) == [
        "eu-west-1", "us-west-2",
    ]
    session.client.assert_not_called()


def test_resolve_sync_regions_discovers_when_none_provided(mocker):
    mocker.patch.object(cartography.intel.aws, "_autodiscover_account_regions", return_value=["us-west-2", "us-east-1"])
    allowed = mocker.patch.object(cartography.intel.aws, "get_allowed_regions", return_value=["us-west-2", "us-east-1"])

    assert cartography.intel.aws._resolve_sync_regions(MagicMock(), "123", []) == ["us-east-1", "us-west-2"]
    allowed.assert_called_once()


def test_resolve_sync_regions_nothing_discovered_does_not_log_error(mocker, caplog):
    mocker.patch.object(cartography.intel.aws, "_autodiscover_account_regions", return_value=[])
    mocker.patch.object(cartography.intel.aws, "get_allowed_regions", return_value=[])

    assert cartography.intel.aws._resolve_sync_regions(MagicMock(), "123", []) == []
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_sync_multiple_accounts_empty_params_does_not_prefill_from_list_all_regions(mocker):
    mocker.patch.object(cartography.intel.aws.organizations, "sync")
    mocker.patch.object(cartography.intel.aws, "list_all_regions", return_value=["ap-south-1"])
    mocker.patch("cartography.intel.aws.boto3.Session")
    captured = {}

    def _capture(*_args, **kwargs):
        captured["regions"] = kwargs.get("regions")

    mocker.patch.object(cartography.intel.aws, "_sync_one_account", side_effect=_capture)

    config = MagicMock()
    config.params = {"regions": []}
    config.credentials = {
        "type": "self",
        "aws_access_key_id": "a",
        "aws_secret_access_key": "b",
    }
    config.update_tag = 1
    config.aws_excluded_regions = ["eu-west-1"]

    cartography.intel.aws._sync_multiple_accounts(
        MagicMock(),
        {"profile": "123"},
        {"Id": "o"},
        config,
        {"AWS_ACCOUNT_ID": "123"},
        False,
        aws_requested_syncs=[],
    )

    assert captured["regions"] == []
    cartography.intel.aws.list_all_regions.assert_not_called()
