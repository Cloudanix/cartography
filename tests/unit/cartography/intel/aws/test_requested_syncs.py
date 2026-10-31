import pytest

import cartography.intel.aws
from cartography.intel.aws.resources import parse_and_validate_aws_requested_syncs


def test_requested_syncs_keeps_known_services_and_records_pagination():
    params = {'pagination': {}}

    syncs = cartography.intel.aws._requested_syncs(
        [{'name': 'sqs'}, {'name': ' appsync '}, {'name': 'dms', 'pagination': {'pageSize': 500}}], params,
    )

    assert syncs == ['sqs', 'appsync', 'dms']
    assert params['pagination'] == {'dms': {'pageSize': 500, 'hasNextPage': False}}


def test_requested_syncs_skips_a_service_this_build_does_not_know(caplog):
    # cloudanix-web may list a service before the cartography build that knows it is deployed.
    syncs = cartography.intel.aws._requested_syncs([{'name': 'sqs'}, {'name': 'not-yet-shipped'}], {'pagination': {}})

    assert syncs == ['sqs']
    assert 'not-yet-shipped' in caplog.text


def test_requested_syncs_with_only_unknown_services_syncs_nothing():
    assert cartography.intel.aws._requested_syncs([{'name': 'not-yet-shipped'}, {}], {'pagination': {}}) == []


def test_cli_validation_still_rejects_an_unknown_service():
    with pytest.raises(ValueError):
        parse_and_validate_aws_requested_syncs('sqs,not-yet-shipped')
