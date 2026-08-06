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
