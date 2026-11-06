import re
from unittest.mock import MagicMock

from cartography.intel.aws import iam

SINGLE_STATEMENT = {
    "Resource": "*",
    "Action": "*",
}

# Example principal field in an AWS policy statement
# see: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html
SINGLE_PRINCIPAL = {
    "AWS": "test-role-1",
    "Service": ["test-service-1", "test-service-2"],
    "Federated": "test-provider-1",
}


def test__generate_policy_statements():
    statements = iam._transform_policy_statements(SINGLE_STATEMENT, "test_policy_id")
    assert isinstance(statements, list)
    assert isinstance(statements[0]["Action"], list)
    assert isinstance(statements[0]["Resource"], list)
    assert statements[0]["id"] == "test_policy_id/statement/1"


def test__parse_principal_entries():
    principal_entries = iam._parse_principal_entries(SINGLE_PRINCIPAL)
    assert isinstance(principal_entries, list)
    assert len(principal_entries) == 4
    assert principal_entries[0] == ("AWS", "test-role-1")
    assert principal_entries[1] == ("Service", "test-service-1")
    assert principal_entries[2] == ("Service", "test-service-2")
    assert principal_entries[3] == ("Federated", "test-provider-1")


def test_get_account_from_arn():
    result = iam.get_account_from_arn("arn:aws:iam::081157660428:role/TestRole")
    assert result == "081157660428"


def test_aws_role_managed_type():
    # Roles AWS reserves for itself are predefined.
    assert iam._aws_role_managed_type("/aws-service-role/access-analyzer.amazonaws.com/") == "predefined"
    assert iam._aws_role_managed_type("/aws-reserved/sso.amazonaws.com/") == "predefined"
    # Console-created service roles are the customer's to edit, so they are custom.
    assert iam._aws_role_managed_type("/service-role/") == "custom"
    # Ordinary customer roles live at "/" or a custom path.
    assert iam._aws_role_managed_type("/") == "custom"
    assert iam._aws_role_managed_type("") == "custom"
    assert iam._aws_role_managed_type(None) == "custom"


def test_get_role_list_data_keeps_console_service_roles_custom():
    # /service-role/ is a service role for JIT (isServiceRole) but custom for compliance rules;
    # the service-linked path is both.
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {"Roles": [{"RoleName": "lambda-role"}, {"RoleName": "AWSServiceRoleForSupport"}]},
    ]
    client.get_role.side_effect = [
        {"Role": {"Path": "/service-role/", "RoleLastUsed": {}}},
        {"Role": {"Path": "/aws-service-role/support.amazonaws.com/", "RoleLastUsed": {}}},
    ]
    session = MagicMock()
    session.client.return_value = client

    roles = iam.get_role_list_data(session)["Roles"]

    assert roles[0]["isServiceRole"] is True
    assert roles[0]["type"] == "custom"
    assert roles[1]["isServiceRole"] is True
    assert roles[1]["type"] == "predefined"


def test_aws_policy_managed_type():
    # AWS-managed policy ARNs use the reserved aws account segment.
    assert iam._aws_policy_managed_type("arn:aws:iam::aws:policy/AdministratorAccess") == "predefined"
    # Customer-managed policy ARNs carry the customer account id.
    assert iam._aws_policy_managed_type("arn:aws:iam::000000000000:policy/my-policy") == "custom"
    assert iam._aws_policy_managed_type("") == "custom"


def test_aws_policy_managed_type_other_partitions():
    assert iam._aws_policy_managed_type("arn:aws-us-gov:iam::aws:policy/ReadOnlyAccess") == "predefined"
    assert iam._aws_policy_managed_type("arn:aws-cn:iam::aws:policy/ReadOnlyAccess") == "predefined"
    assert iam._aws_policy_managed_type("arn:aws-us-gov:iam::000000000000:policy/my-policy") == "custom"


def test_load_policies_cypher_fallback_matches_any_partition():
    tx = MagicMock()
    iam._load_policies_for_account_tx(tx, [{"id": "p", "Arn": "arn:aws-cn:iam::aws:policy/X"}], "000000000000", 1)
    query = tx.run.call_args.args[0]
    pattern = tx.run.call_args.kwargs["aws_managed_policy_arn_pattern"]
    assert "policy.Arn =~ $aws_managed_policy_arn_pattern" in query
    # Cypher =~ is a full match, like re.fullmatch.
    assert re.fullmatch(pattern, "arn:aws-cn:iam::aws:policy/X")
    assert re.fullmatch(pattern, "arn:aws-us-gov:iam::aws:policy/X")
    assert not re.fullmatch(pattern, "arn:aws-cn:iam::000000000000:policy/X")


def test_transform_policies_data_sets_managed_type():
    policies = [
        {"PolicyName": "AdministratorAccess", "Arn": "arn:aws:iam::aws:policy/AdministratorAccess"},
        {"PolicyName": "my-policy", "Arn": "arn:aws:iam::000000000000:policy/my-policy"},
    ]
    result = iam.transform_policies_data("000000000000", policies)
    assert result[0]["managed_type"] == "predefined"
    assert result[1]["managed_type"] == "custom"
    assert result[0]["consolelink"] == (
        "https://console.aws.amazon.com/iam/home?#/policies/arn:aws:iam::aws:policy/AdministratorAccess"
    )


def test_load_policy_data_links_inline_policy_to_its_principal():
    session = MagicMock()
    role_arn = "arn:aws:iam::000000000000:role/app"
    iam.load_policy_data(session, {role_arn: {"inline-pol": []}}, iam.PolicyType.inline.value, "000000000000", 1)

    policy_row = session.execute_write.call_args_list[0].kwargs["DictList"][0]
    assert policy_row["consolelink"] == iam.aws_console_link.get_console_link(arn=role_arn)

    policy_query, sso_policy_query, statement_query = (c.args[1] for c in session.execute_write.call_args_list)
    # Refreshed on every sync, not hidden in the create clause.
    for query in (policy_query, sso_policy_query):
        assert "SET policy.lastupdated = $aws_update_tag, policy.consolelink = item.consolelink" in query
    # Statements carry their policy's link instead of being blanked each sync.
    assert "statement.consolelink = policy.consolelink" in statement_query
    assert "consolelink" not in session.execute_write.call_args_list[2].kwargs


def test_load_policy_data_does_not_invent_an_iam_arn_for_a_permission_set_policy():
    session = MagicMock()
    iam.load_policy_data(session, {"user-1/AdminAccess": {"inline-pol": []}}, iam.PolicyType.inline.value, "0" * 12, 1)

    assert session.execute_write.call_args_list[0].kwargs["DictList"][0]["consolelink"] is None


def test_load_policy_data_leaves_managed_policy_links_to_sync_policies():
    # sync_policies writes the link from the policy's real ARN; a name-built one is wrong for AWS-managed policies.
    session = MagicMock()
    user_arn = "arn:aws:iam::000000000000:user/alice"
    iam.load_policy_data(session, {user_arn: {"AdministratorAccess": []}}, iam.PolicyType.managed.value, "0" * 12, 1)

    assert "policy.consolelink" not in session.execute_write.call_args_list[0].args[1]
