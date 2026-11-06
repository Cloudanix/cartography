"""consolelink values the AWS transforms build with cloudconsolelink."""
from cartography.intel.aws import cloudwatch
from cartography.intel.aws import eks
from cartography.intel.aws import identitystore
from cartography.intel.aws import sns

REGION = "us-east-1"
ACCOUNT_ID = "000000000000"


def test_flow_log_links_the_watched_vpc():
    logs = cloudwatch.transform_flow_logs([{"FlowLogId": "fl-1", "ResourceId": "vpc-1"}], ACCOUNT_ID, REGION)

    # Node id keeps its historical "vcp" spelling so existing nodes are not recreated.
    assert logs[0]["arn"] == f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:vcp-flow-log/fl-1"
    assert logs[0]["consolelink"] == cloudwatch.aws_console_link.get_console_link(
        arn=f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:vpc/vpc-1",
    )


def test_flow_log_on_a_transit_gateway_gets_no_link():
    logs = cloudwatch.transform_flow_logs(
        [{"FlowLogId": "fl-2", "ResourceId": "tgw-attach-1"}, {"FlowLogId": "fl-3", "ResourceId": "tgw-1"}],
        ACCOUNT_ID,
        REGION,
    )

    # No vcp-flow-log template exists, so a fallback would store the EC2 service home as the resource link.
    assert [log["consolelink"] for log in logs] == [None, None]


def test_event_rule_links_its_real_arn():
    arn = f"arn:aws:events:{REGION}:{ACCOUNT_ID}:rule/nightly"
    rules = cloudwatch.transform_rules([{"Name": "nightly", "Arn": arn}], REGION, ACCOUNT_ID)

    assert rules[0]["consolelink"] == (
        f"https://{REGION}.console.aws.amazon.com/events/home?region={REGION}#/rules/nightly"
    )


def test_pending_sns_subscription_gets_no_link():
    subs = sns.transform_subscriptions([{"SubscriptionArn": "PendingConfirmation"}], REGION)

    assert subs[0]["consolelink"] is None


def test_sso_link_opens_the_instance_region():
    link = identitystore.get_sso_console_link("arn:aws:sso:::permissionSet/ssoins-1/ps-1", REGION)

    assert link == f"https://{REGION}.console.aws.amazon.com/singlesignon/home?region={REGION}"


def test_sso_link_is_none_for_a_malformed_arn():
    # Raised IndexError / ARNTooShortError / InvalidPartitionError out of the user and group sync.
    assert identitystore.get_sso_console_link("ssoins-1", REGION) is None
    assert identitystore.get_sso_console_link("arn:aws:sso", REGION) is None
    assert identitystore.get_sso_console_link("arn:bogus:sso:::instance/ssoins-1", REGION) is None
    assert identitystore.get_sso_console_link(None, REGION) is None


def test_eks_cluster_without_arn_gets_no_link():
    clusters = eks.transform([{"name": "c1"}])

    assert clusters[0]["consolelink"] is None
