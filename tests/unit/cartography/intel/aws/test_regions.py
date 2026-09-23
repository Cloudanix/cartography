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
