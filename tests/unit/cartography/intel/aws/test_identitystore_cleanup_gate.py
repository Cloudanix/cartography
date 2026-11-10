"""
sync_identitystore runs the org-wide identity cleanup only after a full sync of the configured Identity Center
instance. The cleanup deletes every org-level permission set, SSO user and group not stamped by this run: with no
matching instance nothing was stamped, and a GROUPS-scoped sync stamps only the scoped users and groups, so either
would delete the org's identities (and the JIT access built on them) that another account's sync loaded.
"""
from unittest.mock import MagicMock

import pytest

from cartography.intel.aws import identitystore

INSTANCE_ARN = 'arn:aws:sso:::instance/ssoins-1'


def _params(**extra):
    return {
        'IDENTITY_STORE_REGION': 'us-east-1',
        'IDENTITY_STORE_IDENTITYFIER': INSTANCE_ARN,
        'ORGANIZATION_ID': 'o-1',
        'WORKSPACE_ID': 'ws-1',
        'UPDATE_TAG': 42,
        **extra,
    }


@pytest.fixture
def stubs(mocker):
    names = (
        'load_identity_center_instance', 'sync_scoped_groups', 'sync_identity_center_users',
        'sync_identity_center_groups', 'sync_identity_center_permissions_sets', 'cleanup_identitystore',
    )
    return {name: mocker.patch.object(identitystore, name) for name in names}


def _run(mocker, instances, params):
    mocker.patch.object(identitystore, 'get_identity_center_instances_list', return_value=instances)
    identitystore.sync_identitystore(MagicMock(), MagicMock(), '111111111111', 42, params)


def test_full_sync_of_the_configured_instance_runs_the_cleanup(mocker, stubs):
    _run(mocker, [{'InstanceArn': INSTANCE_ARN}], _params())

    stubs['sync_identity_center_users'].assert_called_once()
    stubs['cleanup_identitystore'].assert_called_once()


def test_no_matching_instance_skips_the_cleanup(mocker, stubs):
    _run(mocker, [{'InstanceArn': 'arn:aws:sso:::instance/other'}], _params())

    stubs['load_identity_center_instance'].assert_not_called()
    stubs['cleanup_identitystore'].assert_not_called()


def test_no_instance_at_all_skips_the_cleanup(mocker, stubs):
    _run(mocker, [], _params())

    stubs['cleanup_identitystore'].assert_not_called()


def test_groups_scoped_sync_skips_the_org_wide_cleanup(mocker, stubs):
    _run(mocker, [{'InstanceArn': INSTANCE_ARN}], _params(GROUPS=['g-1']))

    stubs['sync_scoped_groups'].assert_called_once()
    stubs['sync_identity_center_users'].assert_not_called()
    stubs['cleanup_identitystore'].assert_not_called()


def test_empty_groups_scope_is_a_full_sync(mocker, stubs):
    _run(mocker, [{'InstanceArn': INSTANCE_ARN}], _params(GROUPS=[]))

    stubs['sync_identity_center_users'].assert_called_once()
    stubs['cleanup_identitystore'].assert_called_once()
