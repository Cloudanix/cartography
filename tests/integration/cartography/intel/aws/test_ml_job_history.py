from unittest.mock import MagicMock

import cartography.intel.aws.bedrock
import cartography.intel.aws.sagemaker
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

OLD_UPDATE_TAG = 111
UPDATE_TAG = 222
ACCOUNT_ID = '777777777775'
REGION = 'us-east-1'


def _boto3_session(pages_by_operation):
    # Every list operation not named returns nothing; the time/status filters are applied by AWS, so the mock
    # returns what AWS would return for the filtered request.
    def get_paginator(operation):
        paginator = MagicMock()
        paginator.paginate.return_value = pages_by_operation.get(operation, [{}])
        return paginator

    client = MagicMock()
    client.get_paginator.side_effect = get_paginator
    session = MagicMock()
    session.client.return_value = client
    return session


def _names(neo4j_session, label):
    rows = neo4j_session.run(
        f"MATCH (:AWSAccount{{id: $account_id}})-[:RESOURCE]->(n:{label}) RETURN n.name AS name",
        account_id=ACCOUNT_ID,
    )
    return {r['name'] for r in rows}


def test_sagemaker_sync_removes_training_jobs_that_fell_out_of_the_window(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-mlh', 'o-mlh', ACCOUNT_ID)
    arn = f'arn:aws:sagemaker:{REGION}:{ACCOUNT_ID}:training-job/'
    # Ingested by an earlier, unfiltered sync.
    cartography.intel.aws.sagemaker.load_training_jobs(
        neo4j_session, [
            {'TrainingJobArn': arn + 'mlh-last-year', 'TrainingJobName': 'mlh-last-year', 'region': REGION},
            {'TrainingJobArn': arn + 'mlh-yesterday', 'TrainingJobName': 'mlh-yesterday', 'region': REGION},
        ], ACCOUNT_ID, OLD_UPDATE_TAG,
    )
    session = _boto3_session({
        'list_training_jobs': [{
            'TrainingJobSummaries': [{'TrainingJobArn': arn + 'mlh-yesterday', 'TrainingJobName': 'mlh-yesterday'}],
        }],
    })

    cartography.intel.aws.sagemaker.sync(
        neo4j_session, session, [REGION], ACCOUNT_ID, UPDATE_TAG,
        exposure_job_parameters('ws-mlh', 'o-mlh', ACCOUNT_ID, UPDATE_TAG),
    )

    assert _names(neo4j_session, 'AWSSagemakerTrainingJob') == {'mlh-yesterday'}


def test_bedrock_sync_removes_customisation_jobs_that_fell_out_of_the_window(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-mlh', 'o-mlh', ACCOUNT_ID)
    arn = f'arn:aws:bedrock:{REGION}:{ACCOUNT_ID}:model-customization-job/'
    cartography.intel.aws.bedrock.load_model_customisation_jobs(
        neo4j_session, [
            {'jobArn': arn + 'mlh-two-years-ago', 'jobName': 'mlh-two-years-ago', 'region': REGION},
            {'jobArn': arn + 'mlh-last-month', 'jobName': 'mlh-last-month', 'region': REGION},
        ], ACCOUNT_ID, OLD_UPDATE_TAG,
    )
    session = _boto3_session({
        'list_model_customization_jobs': [{
            'modelCustomizationJobSummaries': [{'jobArn': arn + 'mlh-last-month', 'jobName': 'mlh-last-month'}],
        }],
    })

    cartography.intel.aws.bedrock.sync(
        neo4j_session, session, [REGION], ACCOUNT_ID, UPDATE_TAG,
        exposure_job_parameters('ws-mlh', 'o-mlh', ACCOUNT_ID, UPDATE_TAG),
    )

    assert _names(neo4j_session, 'AWSBedrockCustomisationJob') == {'mlh-last-month'}
