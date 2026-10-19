from cartography.intel.aws import iam
from cartography.intel.aws.iam import PolicyType
from cartography.intel.aws.iam import transform_policy_data

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


def test__get_role_tags_valid_tags(mocker):
    mocker.patch(
        'cartography.intel.aws.iam.get_role_list_data', return_value={
            'Roles': [
                {
                    'RoleName': 'test-role',
                    'Arn': 'test-arn',
                },
            ],
        },
    )
    mocker.patch('boto3.session.Session')
    mock_session = mocker.Mock()
    mock_client = mocker.Mock()
    mock_role = mocker.Mock()
    mock_role.tags = [
        {
            'Key': 'k1', 'Value': 'v1',
        },
    ]
    mock_client.Role.return_value = mock_role
    mock_session.resource.return_value = mock_client
    result = iam.get_role_tags(mock_session)

    assert result == [{
        'ResourceARN': 'test-arn',
        'Tags': [
            {
                'Key': 'k1',
                'Value': 'v1',
            },
        ],
    }]


def test__get_role_tags_no_tags(mocker):
    mocker.patch(
        'cartography.intel.aws.iam.get_role_list_data', return_value={
            'Roles': [
                {
                    'RoleName': 'test-role',
                    'Arn': 'test-arn',
                },
            ],
        },
    )
    mocker.patch('boto3.session.Session')
    mock_session = mocker.Mock()
    mock_client = mocker.Mock()
    mock_role = mocker.Mock()
    mock_role.tags = [
    ]
    mock_client.Role.return_value = mock_role
    mock_session.resource.return_value = mock_client
    result = iam.get_role_tags(mock_session)

    assert result == []


def test_get_external_access_roles_filters_active_findings(mocker):
    session = mocker.Mock()
    client = session.client.return_value
    client.list_analyzers.return_value = {"analyzers": [{"arn": "analyzer-arn"}]}
    paginator = client.get_paginator.return_value
    paginator.paginate.return_value = [{"findings": [{"resource": "role-arn"}]}]

    result = iam.get_external_access_roles(session, {"DEFAULT_REGION": "us-east-1"})

    assert result == [{"resource": "role-arn"}]
    paginator.paginate.assert_called_once_with(
        analyzerArn="analyzer-arn",
        filter={
            "resourceType": {"eq": ["AWS::IAM::Role"]},
            "status": {"eq": ["ACTIVE"]},
        },
    )


def test_transform_roles_paginates_organization_accounts(mocker):
    session = mocker.Mock()
    paginator = session.client.return_value.get_paginator.return_value
    paginator.paginate.return_value = [
        {"Accounts": [{"Id": "111111111111"}]},
        {"Accounts": [{"Id": "222222222222"}]},
    ]
    roles = [
        {
            "Arn": "arn:aws:iam::000000000000:role/example",
            "AssumeRolePolicyDocument": {
                "Statement": [
                    {
                        "Principal": {
                            "AWS": [
                                "arn:aws:iam::222222222222:root",
                                "arn:aws:iam::333333333333:root",
                            ],
                        },
                    },
                ],
            },
        },
    ]

    result = iam.transform_roles(
        session,
        roles,
        [{"resource": roles[0]["Arn"]}],
        {"AWS_ACCOUNT_ID": "000000000000", "AWS_INTERNAL_ACCOUNTS": []},
    )

    assert result["Roles"][0]["ExternalAccountPrincipals"] == [
        {
            "access_type": "CrossAccount",
            "account_id": "222222222222",
            "principal": "arn:aws:iam::222222222222:root",
        },
        {
            "access_type": "ThirdParty",
            "account_id": "333333333333",
            "principal": "arn:aws:iam::333333333333:root",
        },
    ]
    session.client.return_value.get_paginator.assert_called_once_with("list_accounts")


def test_transform_policy_data_correctly_creates_lists_of_statements():
    # "pol-name" is a policy containing a single statement
    # See https://github.com/lyft/cartography/issues/1102
    pol_statement_map = {
        'some-arn': {
            'pol-name': {
                'Effect': 'Allow',
                'Action': 'secretsmanager:GetSecretValue',
                'Resource': 'arn:aws:secretsmanager:XXXXX:XXXXXXXX',
            },
        },
    }

    # Act: call transform on the object
    transform_policy_data(pol_statement_map, PolicyType.inline.value)

    # Assert that we correctly converted the statement to a list
    assert type(pol_statement_map['some-arn']['pol-name']) == list
