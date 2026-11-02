import datetime

from cartography.intel.aws import iam
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
VENDOR = 'arn:aws:iam::999999999901:root'


def _role(account_id, access_type):
    return {
        'Arn': f'arn:aws:iam::{account_id}:role/vendor-access', 'RoleId': f'{account_id}-role',
        'CreateDate': datetime.datetime(2024, 1, 1), 'RoleName': 'vendor-access', 'Path': '/',
        'AssumeRolePolicyDocument': {'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': VENDOR}}]},
        'ExternalAccountPrincipals': [
            {'principal': VENDOR, 'access_type': access_type, 'account_id': '999999999901'},
        ],
    }


def test_external_principal_access_type_is_per_trusting_role(neo4j_session):
    # 999999999901 is inside the first tenant's organization and a third party to the second tenant.
    for workspace, account_id, access_type in (
        ('ep-ws1', 'ep-a1', 'CrossAccount'), ('ep-ws2', 'ep-b1', 'ThirdParty'),
    ):
        create_test_org_account(neo4j_session, workspace, f'{workspace}-org', account_id)
        iam.load_roles(neo4j_session, [_role(account_id, access_type)], account_id, TEST_UPDATE_TAG)

    trusts = {
        (r['role'], r['access_type']) for r in neo4j_session.run(
            """
            MATCH (role:AWSRole)-[t:TRUSTS_AWS_PRINCIPAL]->(:AWSExternalPrincipal{principal: $vendor})
            RETURN role.arn AS role, t.access_type AS access_type
            """,
            vendor=VENDOR,
        )
    }
    assert trusts == {
        ('arn:aws:iam::ep-a1:role/vendor-access', 'CrossAccount'),
        ('arn:aws:iam::ep-b1:role/vendor-access', 'ThirdParty'),
    }
    # The shared node keeps only global facts, not the last tenant's verdict.
    node = neo4j_session.run(
        "MATCH (p:AWSExternalPrincipal{principal: $vendor}) "
        "RETURN p.access_type AS access_type, p.account_id AS account",
        vendor=VENDOR,
    ).single()
    assert (node['access_type'], node['account']) == (None, '999999999901')
