"""
Unit tests for uniform neo4j interactions in the AWS intel modules
(perf plan Phase 3 items 5+6): every write goes through load_graph_data
(batched UNWIND ingests) or run_write_query (scalar writes), never a raw
auto-commit session.run.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.aws import ecr
from cartography.intel.aws import eks
from cartography.intel.aws import organizations
from cartography.intel.aws import secretsmanager
from cartography.intel.aws import securityhub

TEST_UPDATE_TAG = 123456789
TEST_ACCOUNT_ID = "1234"
TEST_REGION = "us-east-1"


def assert_batched(call, rows):
    assert "UNWIND $DictList" in call.args[1]
    assert call.kwargs["DictList"] == rows


class TestSecretsManager:
    def test_secrets_batched(self):
        session = MagicMock()
        data = [{"ARN": "arn:aws:secretsmanager:us-east-1:1234:secret:s1", "Name": "s1"}]

        secretsmanager.load_secrets(session, data, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, data)

    def test_empty_secrets_write_nothing(self):
        session = MagicMock()
        secretsmanager.load_secrets(session, [], TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()


class TestSecurityHub:
    def test_hub_write_is_managed(self):
        session = MagicMock()

        hub = {"HubArn": "arn:aws:securityhub:us-east-1:1234:hub/default", "SubscribedAt": None}

        securityhub.load_hub(session, hub, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        session.execute_write.assert_called_once()


class TestEcr:
    def test_repositories_batched(self):
        session = MagicMock()
        repos = [{"repositoryArn": "arn:aws:ecr:us-east-1:1234:repository/r1", "repositoryName": "r1"}]

        ecr.load_ecr_repositories(session, repos, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, repos)


class TestEks:
    def test_autoscaling_groups_batched(self):
        session = MagicMock()
        asgs = [{"AutoScalingGroupARN": "arn:aws:autoscaling:us-east-1:1234:autoScalingGroup:g1"}]

        eks.attact_autoscaling_groups_to_nodegroups(session, "arn:nodegroup", asgs, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        call = session.execute_write.call_args
        assert_batched(call, asgs)
        assert call.kwargs["GROUPARN"] == "arn:nodegroup"


class TestOrganizations:
    @patch.object(organizations, "cleanup")
    def test_account_writes_are_managed(self, mock_cleanup):
        session = MagicMock()
        common_job_parameters = {"WORKSPACE_ID": "ws-1", "WORKSPACE_NAME": "ws"}

        organizations.load_aws_accounts(
            session, {"acct-a": "1111", "acct-b": "2222"}, TEST_UPDATE_TAG, {"Id": "o-1"}, common_job_parameters,
        )

        session.run.assert_not_called()
        assert session.execute_write.call_count == 2
