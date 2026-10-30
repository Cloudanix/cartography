import json
from unittest.mock import MagicMock

import cartography.intel.aws
from cartography.intel.aws import lambda_function

API_ARN = "arn:aws:execute-api:us-east-1:111111111111:{}/prod/POST/chat"
APIGATEWAY = "apigateway.amazonaws.com"
ELB = "elasticloadbalancing.amazonaws.com"
TG_ARN = "arn:aws:elasticloadbalancing:us-east-1:111111111111:targetgroup/{}/0123456789abcdef"


def _policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def _statement(service, source_arn=None, effect="Allow"):
    statement = {"Effect": effect, "Principal": {"Service": service}, "Action": "lambda:InvokeFunction"}
    if source_arn:
        statement["Condition"] = {"ArnLike": {"AWS:SourceArn": source_arn}}
    return statement


class TestApiGatewaySourceApiIds:
    def test_api_id_from_source_arn(self):
        policy = _policy(_statement(APIGATEWAY, API_ARN.format("18k4rh88pl")))

        assert lambda_function._extract_apigateway_source_api_ids(policy) == ["18k4rh88pl"]

    def test_ids_from_several_statements_and_arn_lists_are_deduplicated(self):
        policy = _policy(
            _statement(APIGATEWAY, [API_ARN.format("api1"), "arn:aws:execute-api:us-east-1:111111111111:api1/*"]),
            _statement(APIGATEWAY, API_ARN.format("api2")),
        )

        assert lambda_function._extract_apigateway_source_api_ids(policy) == ["api1", "api2"]

    def test_grant_without_source_arn_is_any_source(self):
        # Any API Gateway, in any account, may invoke: cannot be narrowed to one API.
        policy = _policy(_statement(APIGATEWAY))

        assert lambda_function._extract_apigateway_source_api_ids(policy) == [lambda_function.ANY_SOURCE]

    def test_wildcard_api_id_is_kept_and_never_names_a_real_api(self):
        policy = _policy(_statement(APIGATEWAY, "arn:aws:execute-api:us-east-1:111111111111:*/*/*"))

        assert lambda_function._extract_apigateway_source_api_ids(policy) == ["*"]

    def test_deny_and_other_services_are_ignored(self):
        policy = _policy(
            _statement(APIGATEWAY, API_ARN.format("denied"), effect="Deny"),
            _statement(ELB, TG_ARN.format("tg")),
        )

        assert lambda_function._extract_apigateway_source_api_ids(policy) == []

    def test_single_statement_dict_is_accepted(self):
        policy = {"Statement": _statement(APIGATEWAY, API_ARN.format("solo"))}

        assert lambda_function._extract_apigateway_source_api_ids(policy) == ["solo"]


class TestPublicTriggerSources:
    def test_principal_and_source_arn_both_name_the_trigger(self):
        iot_rule = {
            "Effect": "Allow", "Principal": "*",
            "Condition": {"StringEquals": {"aws:SourceArn": "arn:aws:iot:us-east-1:1:rule/r"}},
        }
        policy = _policy(_statement(APIGATEWAY, API_ARN.format("api1")), _statement(ELB), iot_rule)

        assert lambda_function._extract_public_trigger_sources(policy) == ["alb", "apigateway", "iot"]

    def test_deny_statements_are_ignored(self):
        policy = _policy(_statement(APIGATEWAY, API_ARN.format("api1"), effect="Deny"))

        assert lambda_function._extract_public_trigger_sources(policy) == []


def test_get_lambda_policies_stores_source_refs():
    client = MagicMock()
    client.get_policy.return_value = {"Policy": json.dumps(_policy(_statement(APIGATEWAY, API_ARN.format("api1"))))}
    session = MagicMock()
    session.client.return_value = client
    functions = [{"FunctionArn": "arn:aws:lambda:us-east-1:111111111111:function:f"}]

    lambda_function.get_lambda_policies(session, "us-east-1", functions)

    assert functions[0]["public_trigger_sources"] == ["apigateway"]
    assert functions[0]["apigateway_source_api_ids"] == ["api1"]


def test_load_writes_source_refs():
    session = MagicMock()

    lambda_function.load_lambda_functions(session, [{"FunctionArn": "arn"}], "111111111111", 1)

    query = session.execute_write.call_args.args[1]
    assert "lambda.apigateway_source_api_ids = lf.apigateway_source_api_ids" in query


def test_lambda_exposure_runs_after_the_jobs_it_reads(mocker, monkeypatch):
    # The Lambda job reads APIGatewayRestAPI / LoadBalancerV2 exposure, so it must run after both.
    monkeypatch.setenv("LOCAL_RUN", "1")
    jobs = []
    mocker.patch.dict(cartography.intel.aws.RESOURCE_FUNCTIONS, {}, clear=True)
    mocker.patch.object(cartography.intel.aws, "_resolve_sync_regions", return_value=["us-east-1"])
    mocker.patch.object(cartography.intel.aws, "_build_aws_sync_kwargs", return_value={})
    mocker.patch.object(cartography.intel.aws, "run_cleanup_job")
    mocker.patch.object(cartography.intel.aws, "run_analysis_job", side_effect=lambda name, *_: jobs.append(name))
    config = MagicMock()
    config.aws_excluded_regions = None
    config.refresh_entitlements = False

    cartography.intel.aws._sync_one_account(
        MagicMock(), MagicMock(), "111111111111", 42,
        {"WORKSPACE_ID": "ws-1", "AWS_ID": "111111111111", "UPDATE_TAG": 42}, ["us-east-1"], [],
        creds={}, config=config,
    )

    lambda_job = jobs.index("aws_lambda_function_asset_exposure.json")
    assert lambda_job > jobs.index("aws_apigateway_asset_exposure.json")
    assert lambda_job > jobs.index("aws_ec2_elb_asset_exposure.json")
