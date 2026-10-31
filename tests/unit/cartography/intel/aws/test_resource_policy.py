import json

import pytest

from cartography.intel.aws.util.common import is_resource_policy_internet_accessible

TOPIC = 'arn:aws:sns:us-east-1:111111111111:alerts'


def _policy(*statements):
    return json.dumps({'Version': '2012-10-17', 'Statement': list(statements)})


def _allow(principal, condition=None):
    statement = {'Effect': 'Allow', 'Principal': principal, 'Action': 'SNS:Publish', 'Resource': TOPIC}
    if condition:
        statement['Condition'] = condition
    return statement


@pytest.mark.parametrize(
    'principal', ['*', {'AWS': '*'}, {'AWS': ['*']}],
)
def test_open_principal_without_condition_is_internet_accessible(principal):
    assert is_resource_policy_internet_accessible(_policy(_allow(principal))) is True


@pytest.mark.parametrize(
    'condition', [
        {'StringEquals': {'aws:SourceAccount': '111111111111'}},
        {'ArnLike': {'aws:SourceArn': 'arn:aws:s3:::my-bucket'}},
        {'StringEquals': {'AWS:SourceOwner': '111111111111'}},
        {'StringEquals': {'aws:SourceOrgID': 'o-abc123'}},
        {'ForAnyValue:StringLike': {'aws:SourceOrgPaths': 'o-abc123/r-ab12/ou-ab12-11111111/*'}},
        {'StringEquals': {'aws:PrincipalOrgID': 'o-abc123'}},
        {'StringEquals': {'aws:SourceVpc': 'vpc-111'}},
        {'StringEquals': {'aws:SourceVpce': 'vpce-111'}},
    ],
)
def test_open_principal_restricted_by_condition_is_not_internet_accessible(condition):
    assert is_resource_policy_internet_accessible(_policy(_allow('*', condition))) is False


def test_wildcard_condition_value_does_not_restrict():
    condition = {'StringLike': {'aws:SourceOrgID': '*'}}
    assert is_resource_policy_internet_accessible(_policy(_allow('*', condition))) is True


def test_named_principals_and_deny_are_not_internet_accessible():
    deny = {'Effect': 'Deny', 'Principal': '*', 'Action': 'SNS:Publish', 'Resource': TOPIC}
    policy = _policy(_allow({'AWS': 'arn:aws:iam::111111111111:root'}), deny)
    assert is_resource_policy_internet_accessible(policy) is False


def test_one_open_statement_among_restricted_ones_is_internet_accessible():
    policy = _policy(
        _allow('*', {'StringEquals': {'aws:SourceAccount': '111111111111'}}),
        _allow({'AWS': '*'}),
    )
    assert is_resource_policy_internet_accessible(policy) is True


def test_single_statement_object_is_read():
    policy = json.dumps({'Version': '2012-10-17', 'Statement': _allow('*')})
    assert is_resource_policy_internet_accessible(policy) is True


def test_no_policy_is_not_internet_accessible():
    assert is_resource_policy_internet_accessible(None) is False
    assert is_resource_policy_internet_accessible('') is False


def test_unparseable_policy_is_unknown():
    assert is_resource_policy_internet_accessible('{not json') is None
