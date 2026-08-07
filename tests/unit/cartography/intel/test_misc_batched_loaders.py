"""
Unit tests for the Phase 3.6 batched loaders in the small intel modules:
github/repos, aws/rds, azure/subscription, digitalocean/compute.
"""
from unittest.mock import MagicMock

from cartography.intel.aws import rds
from cartography.intel.digitalocean import compute as do_compute
from cartography.intel.github import repos

TEST_UPDATE_TAG = 123456789


class TestGithubOwners:
    def test_single_batched_write(self):
        session = MagicMock()
        owners = [
            {"type": "Organization", "owner": "acme", "repo_id": "https://github.com/acme/a"},
            {"type": "Organization", "owner": "acme", "repo_id": "https://github.com/acme/b"},
        ]

        repos.load_github_owners(session, TEST_UPDATE_TAG, owners)

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert "GitHubOrganization" in call.args[1]
        assert call.kwargs["DictList"] == [
            {"owner": "acme", "repo_id": "https://github.com/acme/a"},
            {"owner": "acme", "repo_id": "https://github.com/acme/b"},
        ]

    def test_empty_owners_write_nothing(self):
        session = MagicMock()
        repos.load_github_owners(session, TEST_UPDATE_TAG, [])
        session.execute_write.assert_not_called()


class TestRdsBatchedAttachments:
    def test_db_security_groups_flattened(self):
        session = MagicMock()
        db_sgs = [
            {
                "DBSecurityGroupArn": "arn:dbsg/1",
                "EC2SecurityGroups": [{"EC2SecurityGroupId": "sg-1"}, {"EC2SecurityGroupId": "sg-2"}],
            },
            {"DBSecurityGroupArn": "arn:dbsg/2", "EC2SecurityGroups": []},
        ]

        rds.attach_db_security_groups_to_ec2_security_groups(session, db_sgs, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        rows = session.execute_write.call_args.kwargs["DictList"]
        assert rows == [
            {"db_sg_id": "arn:dbsg/1", "ec2_sg_id": "sg-1"},
            {"db_sg_id": "arn:dbsg/1", "ec2_sg_id": "sg-2"},
        ]

    def test_associated_roles_flattened(self):
        session = MagicMock()
        clusters = [
            {"DBClusterArn": "arn:cluster/1", "AssociatedRoles": [{"RoleArn": "arn:role/1"}]},
            {"DBClusterArn": "arn:cluster/2", "AssociatedRoles": []},
        ]

        rds._attach_associate_roles(session, clusters, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        rows = session.execute_write.call_args.kwargs["DictList"]
        assert rows == [{"cluster_arn": "arn:cluster/1", "role_arn": "arn:role/1"}]


# NOTE azure/subscription.py's batched loader is validated by py_compile/flake8 here and
# integration in CI: the azure package __init__ imports SDK modules unavailable in the
# dev sandbox, so it cannot be imported by unit tests (same as azure/compute.py).


class TestDigitaloceanDroplets:
    def test_single_batched_write(self):
        session = MagicMock()
        droplets = [{"id": "d1", "project_id": "p1", "name": "web"}]

        do_compute.load_droplets(session, droplets, TEST_UPDATE_TAG)

        assert session.execute_write.call_count == 1
        call = session.execute_write.call_args
        assert "UNWIND $DictList" in call.args[1]
        assert call.kwargs["DictList"] == droplets

    def test_empty_droplets_write_nothing(self):
        session = MagicMock()
        do_compute.load_droplets(session, [], TEST_UPDATE_TAG)
        session.execute_write.assert_not_called()
