import json

import cartography.intel.aws.sagemaker
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777776'
OTHER_ACCOUNT_ID = '888888888886'


def _arn(account_id, name):
    return f'arn:aws:sagemaker:us-east-1:{account_id}:notebook-instance/{name}'


def _load(neo4j_session, account_id, notebooks):
    # Shape of get_notebook_instances_list() output.
    cartography.intel.aws.sagemaker.load_notebook_instances(
        neo4j_session, [
            {
                'NotebookInstanceArn': _arn(account_id, name), 'NotebookInstanceName': name,
                'NotebookInstanceStatus': 'InService', 'region': 'us-east-1', 'DirectInternetAccess': access,
            }
            for name, access in notebooks
        ], account_id, TEST_UPDATE_TAG,
    )


def test_sagemaker_notebook_public_when_direct_internet_access_is_enabled(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-smx', 'o-smx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-smx-other', 'o-smx-other', OTHER_ACCOUNT_ID)
    _load(
        neo4j_session, ACCOUNT_ID, [
            ('smx-direct', 'Enabled'), ('smx-vpc-only', 'Disabled'), ('smx-unknown', None),
            ('smx-disabled-since', 'Disabled'),
        ],
    )
    _load(neo4j_session, OTHER_ACCOUNT_ID, [('smx-other-direct', 'Enabled')])
    neo4j_session.run(
        "MATCH (n:AWSSagemakerNotebookInstance{name: 'smx-disabled-since'}) "
        "SET n.exposed_internet = true, n.exposed_internet_type = ['direct_internet_access']",
    )

    run_analysis_job(
        'aws_sagemaker_notebook_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-smx', 'o-smx', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (n:AWSSagemakerNotebookInstance) RETURN n.name AS name, n.exposed_internet AS exposed, "
        "n.exposed_internet_type AS types, n.publicContext AS context",
    )
    notebooks = {r['name']: r for r in rows}
    assert {n for n, r in notebooks.items() if r['exposed']} == {'smx-direct'}
    assert notebooks['smx-direct']['types'] == ['direct_internet_access']
    context = json.loads(notebooks['smx-direct']['context'])[0]
    assert (context['resource'], context['resourceType']) == (
        _arn(ACCOUNT_ID, 'smx-direct'), 'aws-ai-sagemaker-instance',
    )
    assert notebooks['smx-disabled-since']['context'] is None
