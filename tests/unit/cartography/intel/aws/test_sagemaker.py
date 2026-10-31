from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from cartography.intel.aws import sagemaker

ARN = 'arn:aws:sagemaker:us-east-1:111111111111:notebook-instance/'


def test_get_notebook_instances_list_reads_direct_internet_access():
    client = MagicMock()
    client.get_paginator.return_value.paginate.return_value = [
        {
            'NotebookInstances': [
                {'NotebookInstanceName': 'nb-open', 'NotebookInstanceArn': ARN + 'nb-open'},
                {'NotebookInstanceName': 'nb-vpc-only', 'NotebookInstanceArn': ARN + 'nb-vpc-only'},
                {'NotebookInstanceName': 'nb-denied', 'NotebookInstanceArn': ARN + 'nb-denied'},
            ],
        },
    ]
    # Shape of describe_notebook_instance(); list_notebook_instances does not return DirectInternetAccess.
    described = {
        'nb-open': {'NotebookInstanceName': 'nb-open', 'DirectInternetAccess': 'Enabled'},
        'nb-vpc-only': {
            'NotebookInstanceName': 'nb-vpc-only', 'DirectInternetAccess': 'Disabled', 'SubnetId': 'subnet-1',
        },
    }

    def describe(NotebookInstanceName):
        if NotebookInstanceName not in described:
            raise ClientError(
                {'Error': {'Code': 'AccessDeniedException', 'Message': 'denied'}}, 'DescribeNotebookInstance',
            )
        return described[NotebookInstanceName]

    client.describe_notebook_instance.side_effect = describe
    session = MagicMock()
    session.client.return_value = client

    instances = sagemaker.get_notebook_instances_list(session, 'us-east-1')

    assert {i['NotebookInstanceName']: i['DirectInternetAccess'] for i in instances} == {
        'nb-open': 'Enabled',
        'nb-vpc-only': 'Disabled',
        # Unknown: not flagged.
        'nb-denied': None,
    }
