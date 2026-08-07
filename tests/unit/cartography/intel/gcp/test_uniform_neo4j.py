"""
Unit tests for uniform neo4j interactions in the gcp intel modules
(perf plan Phase 3 items 5+6).
"""
from unittest.mock import MagicMock

from cartography.intel.gcp import crm
from cartography.intel.gcp import dns
from cartography.intel.gcp import iam
from cartography.intel.gcp import workspace

TEST_UPDATE_TAG = 123456789
TEST_PROJECT_ID = "project-1"


def assert_batched(call, rows):
    assert "UNWIND $DictList" in call.args[1]
    assert call.kwargs["DictList"] == rows


class TestDns:
    def test_zones_records_policies_keys_batched(self):
        session = MagicMock()
        zones = [{"id": "z1", "name": "example.com"}]
        rrs = [{"id": "rr1", "name": "www", "zone": "z1"}]
        policies = [{"id": "p1", "name": "policy"}]
        keys = [{"id": "k1", "keyTag": 1}]

        dns.load_dns_zones(session, zones, TEST_PROJECT_ID, TEST_UPDATE_TAG)
        dns.load_rrs(session, rrs, TEST_PROJECT_ID, TEST_UPDATE_TAG)
        dns.load_dns_polices(session, policies, TEST_PROJECT_ID, TEST_UPDATE_TAG)
        dns.load_dns_keys(session, keys, TEST_PROJECT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert session.execute_write.call_count == 4
        for call, rows in zip(session.execute_write.call_args_list, [zones, rrs, policies, keys]):
            assert_batched(call, rows)


class TestIam:
    def test_service_accounts_and_roles_batched(self):
        session = MagicMock()
        # email is left unset: _gcp_service_account_managed_type handles None.
        service_accounts = [{"uniqueId": "sa-1", "email": None}]
        roles = [{"id": "roles/viewer", "name": "roles/viewer"}]

        iam.load_service_accounts(session, service_accounts, TEST_PROJECT_ID, TEST_UPDATE_TAG)
        iam.load_project_roles(session, roles, TEST_PROJECT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert session.execute_write.call_count == 2
        assert_batched(session.execute_write.call_args_list[0], service_accounts)
        assert_batched(session.execute_write.call_args_list[1], roles)

    def test_api_keys_batched(self):
        session = MagicMock()
        api_keys = [{"uid": "key-1", "name": "projects/p/keys/key-1"}]

        iam.load_api_keys(session, api_keys, TEST_PROJECT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, api_keys)


class TestCrmManagedWrites:
    def test_organization_write_is_managed(self):
        session = MagicMock()
        orgs = [{"name": "organizations/1", "displayName": "acme", "lifecycleState": "ACTIVE"}]

        crm.load_gcp_organizations(session, orgs, TEST_UPDATE_TAG, {"WORKSPACE_ID": "ws-1"})

        session.run.assert_not_called()
        session.execute_write.assert_called_once()


class TestWorkspace:
    def test_group_members_batched(self):
        session = MagicMock()
        members = [{"id": "member-1", "type": "USER"}]

        workspace.load_groups_members(session, {"id": "g1"}, members, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert session.execute_write.call_count >= 1
        assert_batched(session.execute_write.call_args_list[0], members)
