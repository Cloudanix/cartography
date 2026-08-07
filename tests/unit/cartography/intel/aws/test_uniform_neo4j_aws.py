"""
Unit tests for uniform neo4j interactions in the AWS intel modules
(perf plan Phase 3 items 5+6): every write goes through load_graph_data
(batched UNWIND ingests) or run_write_query (scalar writes), never a raw
auto-commit session.run.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

from cartography.intel.aws import apigateway
from cartography.intel.aws import config
from cartography.intel.aws import ecr
from cartography.intel.aws import eks
from cartography.intel.aws import elasticache
from cartography.intel.aws import ecs
from cartography.intel.aws import elasticsearch
from cartography.intel.aws import kms
from cartography.intel.aws import lambda_function
from cartography.intel.aws import organizations
from cartography.intel.aws import secretsmanager
from cartography.intel.aws import securityhub
from cartography.intel.aws import sqs

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


class TestConfig:
    def test_recorders_channels_rules_batched(self):
        session = MagicMock()
        recorders = [{"name": "default", "roleARN": "arn:aws:iam::1234:role/config"}]
        channels = [{"name": "default", "s3BucketName": "b1"}]
        rules = [{"ConfigRuleArn": "arn:aws:config:us-east-1:1234:config-rule/r1", "ConfigRuleName": "r1"}]

        config.load_configuration_recorders(session, recorders, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        config.load_delivery_channels(session, channels, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        config.load_config_rules(session, rules, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert session.execute_write.call_count == 3
        for call in session.execute_write.call_args_list:
            assert "UNWIND $DictList" in call.args[1]
            assert len(call.kwargs["DictList"]) == 1


class TestElasticache:
    def test_clusters_and_security_groups_batched(self):
        session = MagicMock()
        clusters = [{"ARN": "arn:aws:elasticache:us-east-1:1234:cluster:c1", "SecurityGroups": []}]

        elasticache.load_elasticache_clusters(session, clusters, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        elasticache.attach_elasticache_clusters_to_security_groups(session, clusters, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert session.execute_write.call_count == 2
        for call in session.execute_write.call_args_list:
            assert_batched(call, clusters)


class TestSqs:
    def test_queues_and_deadletter_links_batched(self):
        session = MagicMock()
        queue_arn = "arn:aws:sqs:us-east-1:1234:q1"
        data = {
            "https://sqs/q1": {
                "QueueArn": queue_arn,
                "CreatedTimestamp": "1700000000",
                "LastModifiedTimestamp": "1700000000",
                "RedrivePolicy": '{"deadLetterTargetArn": "arn:aws:sqs:us-east-1:1234:dlq"}',
            },
        }

        sqs.load_sqs_queues(session, data, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        # one batch for queues, one for the dead-letter relationships
        assert session.execute_write.call_count == 2
        dlq_rows = session.execute_write.call_args_list[1].kwargs["DictList"]
        assert dlq_rows == [{"arn": queue_arn, "dead_letter_arn": "arn:aws:sqs:us-east-1:1234:dlq"}]


class TestKms:
    def test_aliases_batched(self):
        session = MagicMock()
        aliases = [{"AliasArn": "arn:aws:kms:us-east-1:1234:alias/a1", "TargetKeyId": "k1"}]

        kms._load_kms_key_aliases(session, aliases, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert_batched(session.execute_write.call_args, aliases)

    def test_default_values_write_is_managed(self):
        session = MagicMock()

        kms._set_default_values(session, TEST_ACCOUNT_ID)

        session.run.assert_not_called()
        session.execute_write.assert_called_once()


class TestElasticsearch:
    def test_access_policy_tag_write_is_managed(self):
        session = MagicMock()

        elasticsearch._process_access_policy(session, "domain-1", {"Endpoint": None})

        session.run.assert_not_called()
        session.execute_write.assert_called_once()

    def test_vpc_links_batched_and_skipped_when_empty(self):
        session = MagicMock()
        domain = {"VPCOptions": {"SubnetIds": ["subnet-1"], "SecurityGroupIds": []}}

        elasticsearch._link_es_domain_vpc(session, "domain-1", domain, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        # subnets batch writes; the empty security-group list short-circuits
        assert session.execute_write.call_count == 1
        assert session.execute_write.call_args.kwargs["DictList"] == ["subnet-1"]


class TestApiGateway:
    def test_rest_apis_and_stages_batched(self):
        session = MagicMock()
        apis = [{"id": "a1", "region": TEST_REGION, "createdDate": "2024-01-01"}]
        stages = [{"apiId": "a1", "stageName": "prod", "region": TEST_REGION, "createdDate": "2024-01-01"}]

        apigateway.load_apigateway_rest_apis(session, apis, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        apigateway._load_apigateway_stages(session, stages, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert session.execute_write.call_count == 2
        for call in session.execute_write.call_args_list:
            assert "UNWIND $DictList" in call.args[1]

    def test_default_values_write_is_managed(self):
        session = MagicMock()

        apigateway._set_default_values(session, TEST_ACCOUNT_ID)

        session.run.assert_not_called()
        session.execute_write.assert_called_once()


class TestEcs:
    def test_clusters_and_services_batched(self):
        session = MagicMock()
        clusters = [{"clusterArn": "arn:aws:ecs:us-east-1:1234:cluster/c1"}]
        services = [{"serviceArn": "arn:aws:ecs:us-east-1:1234:service/s1", "createdAt": None}]

        ecs.load_ecs_clusters(session, clusters, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        ecs.load_ecs_services(
            session, "arn:aws:ecs:us-east-1:1234:cluster/c1", services, TEST_REGION, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
        )

        session.run.assert_not_called()
        assert session.execute_write.call_count == 2
        assert_batched(session.execute_write.call_args_list[0], clusters)
        service_call = session.execute_write.call_args_list[1]
        assert_batched(service_call, services)
        assert service_call.kwargs["ClusterARN"] == "arn:aws:ecs:us-east-1:1234:cluster/c1"


class TestLambda:
    def test_functions_and_aliases_batched(self):
        session = MagicMock()
        functions = [{"FunctionArn": "arn:aws:lambda:us-east-1:1234:function:f1", "FunctionName": "f1"}]
        aliases = [{"AliasArn": "arn:aws:lambda:us-east-1:1234:function:f1:live", "FunctionArn": "f1"}]

        lambda_function.load_lambda_functions(session, functions, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
        lambda_function._load_lambda_function_aliases(session, aliases, TEST_UPDATE_TAG)

        session.run.assert_not_called()
        assert session.execute_write.call_count == 2
        assert_batched(session.execute_write.call_args_list[0], functions)
        assert_batched(session.execute_write.call_args_list[1], aliases)
