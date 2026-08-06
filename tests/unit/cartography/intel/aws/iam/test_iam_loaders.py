"""
Unit tests for the batched (UNWIND $DictList) IAM loaders (perf plan Phase 3.2).
A MagicMock session records the execute_write calls issued by load_graph_data.
"""
from unittest.mock import MagicMock

from cartography.intel.aws import iam

TEST_UPDATE_TAG = 123456789
TEST_ACCOUNT_ID = "1234"

USER = {
    "Arn": "arn:aws:iam::1234:user/alice",
    "UserId": "AIDA1",
    "CreateDate": "2024-01-01",
    "UserName": "alice",
    "Path": "/",
    "PasswordLastUsed": "2024-02-01",
}

GROUP = {
    "Arn": "arn:aws:iam::1234:group/admins",
    "GroupId": "AGPA1",
    "CreateDate": "2024-01-01",
    "GroupName": "admins",
    "Path": "/",
}


class TestLoadUsers:
    def test_single_batched_write(self):
        session = MagicMock()

        iam.load_users(session, [USER, {**USER, "Arn": "arn:aws:iam::1234:user/bob", "UserName": "bob"}],
                       TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert "UNWIND $DictList AS item" in call.args[1]
        rows = call.kwargs["DictList"]
        assert len(rows) == 2
        assert rows[0]["arn"] == USER["Arn"]
        assert rows[0]["username"] == "alice"
        assert rows[0]["passwordlastused"] == "2024-02-01"
        assert call.kwargs["AWS_ACCOUNT_ID"] == TEST_ACCOUNT_ID
        assert call.kwargs["aws_update_tag"] == TEST_UPDATE_TAG

    def test_empty_list_writes_nothing(self):
        session = MagicMock()
        iam.load_users(session, [], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()


class TestLoadServiceAccounts:
    def test_single_batched_write(self):
        session = MagicMock()

        iam.load_service_accounts(session, [USER], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert "AWSServiceAccount" in call.args[1]
        assert call.kwargs["DictList"][0]["arn"] == USER["Arn"]


ROLE = {
    "Arn": "arn:aws:iam::1234:role/app-role",
    "RoleId": "AROA1",
    "CreateDate": "2024-01-01",
    "RoleName": "app-role",
    "Path": "/",
    "RoleLastUsed": {"LastUsedDate": "2024-03-01", "Region": "us-east-1"},
    "ExternalAccountPrincipals": [
        {"principal": "arn:aws:iam::9999:root", "access_type": "cross-account", "account_id": "9999"},
    ],
    "AssumeRolePolicyDocument": {
        "Statement": [
            {"Principal": {"Service": "ec2.amazonaws.com", "AWS": ["arn:aws:iam::1234:root"]}},
        ],
    },
}


class TestLoadRoles:
    def test_three_batched_writes(self):
        session = MagicMock()

        iam.load_roles(session, [ROLE, ROLE], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        # roles + external principals + trust principals = 3 writes total,
        # regardless of role count (was 1 + 1 + 2 writes PER role).
        assert session.execute_write.call_count == 3
        role_call, external_call, trust_call = session.execute_write.call_args_list

        assert "AWSRole" in role_call.args[1]
        assert len(role_call.kwargs["DictList"]) == 2
        assert role_call.kwargs["DictList"][0]["lastuseddate"] == "2024-03-01"

        assert "AWSExternalPrincipal" in external_call.args[1]
        assert external_call.kwargs["DictList"] == [
            {
                "principal": "arn:aws:iam::9999:root", "access_type": "cross-account",
                "account_id": "9999", "role_arn": ROLE["Arn"],
            },
        ] * 2

        # 2 principal entries per role (Service + AWS list entry) x 2 roles
        assert "TRUSTS_AWS_PRINCIPAL" in trust_call.args[1]
        trust_rows = trust_call.kwargs["DictList"]
        assert len(trust_rows) == 4
        assert {(r["spn_type"], r["spn_arn"]) for r in trust_rows} == {
            ("Service", "ec2.amazonaws.com"),
            ("AWS", "arn:aws:iam::1234:root"),
        }

    def test_empty_list_writes_nothing(self):
        session = MagicMock()
        iam.load_roles(session, [], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()


class TestLoadGroups:
    def test_single_batched_write(self):
        session = MagicMock()

        iam.load_groups(session, [GROUP], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert "UNWIND $DictList AS item" in call.args[1]
        assert call.kwargs["DictList"] == [{
            "arn": GROUP["Arn"],
            "consolelink": call.kwargs["DictList"][0]["consolelink"],
            "groupid": "AGPA1",
            "createdate": "2024-01-01",
            "groupname": "admins",
            "path": "/",
        }]

    def test_empty_list_writes_nothing(self):
        session = MagicMock()
        iam.load_groups(session, [], TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()


class TestLoadGroupMemberships:
    def test_single_batched_write(self):
        session = MagicMock()
        memberships = {
            "arn:aws:iam::1234:group/admins": {"Users": [{"Arn": "arn:aws:iam::1234:user/alice"}]},
            "arn:aws:iam::1234:group/devs": {
                "Users": [{"Arn": "arn:aws:iam::1234:user/alice"}, {"Arn": "arn:aws:iam::1234:user/bob"}],
            },
        }

        iam.load_group_memberships(session, memberships, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        rows = session.execute_write.call_args.kwargs["DictList"]
        assert len(rows) == 3
        assert {"group_arn": "arn:aws:iam::1234:group/devs", "principal_arn": "arn:aws:iam::1234:user/bob"} in rows

    def test_empty_memberships_write_nothing(self):
        session = MagicMock()
        iam.load_group_memberships(session, {}, TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()


class TestLoadUserAccessKeys:
    def test_single_batched_write_skips_keyless_entries(self):
        session = MagicMock()
        access_keys = {
            "arn:aws:iam::1234:user/alice": {
                "AccessKeyMetadata": [
                    {"AccessKeyId": "AKIA1", "Status": "Active", "CreateDate": "2024-01-01"},
                    {"Status": "Inactive"},  # no AccessKeyId -> skipped, as before
                ],
            },
        }

        iam.load_user_access_keys(session, access_keys, TEST_UPDATE_TAG, "https://console")

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert call.kwargs["DictList"] == [{
            "arn": "arn:aws:iam::1234:user/alice",
            "accesskeyid": "AKIA1",
            "lastuseddate": "",
            "createdate": "2024-01-01",
            "keyage": "",
            "status": "Active",
        }]
        assert call.kwargs["consolelink"] == "https://console"

    def test_empty_keys_write_nothing(self):
        session = MagicMock()
        iam.load_user_access_keys(session, {}, TEST_UPDATE_TAG, "https://console")
        session.execute_write.assert_not_called()
