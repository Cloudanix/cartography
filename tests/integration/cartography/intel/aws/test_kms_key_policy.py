import json

import cartography.intel.aws.kms
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
REGION = 'us-east-1'
ACCOUNT_ID = '777777777791'
OTHER_ACCOUNT_ID = '888888888891'
PUBLIC_KEY_ID = 'kmspol-public-key'
PRIVATE_KEY_ID = 'kmspol-private-key'
OTHER_KEY_ID = 'kmspol-other-tenant-key'

PUBLIC_POLICY = {
    'Policy': json.dumps({
        'Version': '2012-10-17',
        'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': 'kms:Decrypt', 'Resource': '*'}],
    }),
}
PRIVATE_POLICY = {
    'Policy': json.dumps({
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow', 'Principal': {'AWS': f'arn:aws:iam::{ACCOUNT_ID}:root'},
            'Action': 'kms:*', 'Resource': '*',
        }],
    }),
}


def _key(key_id, account_id):
    return {
        'KeyId': key_id,
        'Arn': f'arn:aws:kms:{REGION}:{account_id}:key/{key_id}',
        'CreationDate': '2026-01-01 00:00:00',
        'Enabled': True,
        'KeyState': 'Enabled',
        'KeyManager': 'CUSTOMER',
        'region': REGION,
    }


def _sync_details(neo4j_session, account_id, workspace_id, org_id, policies):
    cartography.intel.aws.kms.load_kms_key_details(
        neo4j_session,
        [(key_id, policy, [], [], REGION) for key_id, policy in policies],
        account_id,
        TEST_UPDATE_TAG,
        exposure_job_parameters(workspace_id, org_id, account_id, TEST_UPDATE_TAG),
    )


def _exposure(neo4j_session, key_id):
    row = neo4j_session.run(
        "MATCH (k:KMSKey{id: $id}) RETURN k.anonymous_access AS access, k.anonymous_actions AS actions",
        id=key_id,
    ).single()
    return row['access'], row['actions']


def test_key_policy_exposure_is_applied_to_the_accounts_own_keys_only(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-kmspol', 'o-kmspol', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-kmspol-other', 'o-kmspol-other', OTHER_ACCOUNT_ID)
    cartography.intel.aws.kms.load_kms_keys(
        neo4j_session, [_key(PUBLIC_KEY_ID, ACCOUNT_ID), _key(PRIVATE_KEY_ID, ACCOUNT_ID)],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.kms.load_kms_keys(
        neo4j_session, [_key(OTHER_KEY_ID, OTHER_ACCOUNT_ID)], OTHER_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    _sync_details(
        neo4j_session, ACCOUNT_ID, 'ws-kmspol', 'o-kmspol',
        # A policy result naming another tenant's key id must not write onto that key.
        [(PUBLIC_KEY_ID, PUBLIC_POLICY), (PRIVATE_KEY_ID, PRIVATE_POLICY), (OTHER_KEY_ID, PUBLIC_POLICY)],
    )
    _sync_details(neo4j_session, OTHER_ACCOUNT_ID, 'ws-kmspol-other', 'o-kmspol-other', [])

    assert _exposure(neo4j_session, PUBLIC_KEY_ID) == (True, ['kms:Decrypt'])
    assert _exposure(neo4j_session, PRIVATE_KEY_ID) == (False, [])
    assert _exposure(neo4j_session, OTHER_KEY_ID) == (False, [])


def test_key_policy_exposure_does_not_accumulate_across_syncs(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-kmspol', 'o-kmspol', ACCOUNT_ID)
    for _ in range(2):
        _sync_details(neo4j_session, ACCOUNT_ID, 'ws-kmspol', 'o-kmspol', [(PUBLIC_KEY_ID, PUBLIC_POLICY)])

    assert _exposure(neo4j_session, PUBLIC_KEY_ID) == (True, ['kms:Decrypt'])
