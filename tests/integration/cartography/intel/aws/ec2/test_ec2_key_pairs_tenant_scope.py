from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
FINGERPRINT = '44:44:44:44:44:44:44:44:44:44:44:44:44:44:44:44'
WORKSPACE, ORG = 'kp-ws1', 'kp-o1'
OTHER_WORKSPACE, OTHER_ORG = 'kp-ws2', 'kp-o2'
ACCOUNT, SIBLING_ACCOUNT, OTHER_ACCOUNT = 'kp-a1', 'kp-a2', 'kp-b1'


def _key(account_id):
    return f'arn:aws:ec2:us-east-1:{account_id}:key-pair/deploy'


def _seed(neo4j_session):
    # The same uploaded key in two accounts of one workspace, and in another tenant.
    create_test_org_account(neo4j_session, WORKSPACE, ORG, ACCOUNT)
    create_test_org_account(neo4j_session, WORKSPACE, ORG, SIBLING_ACCOUNT)
    create_test_org_account(neo4j_session, OTHER_WORKSPACE, OTHER_ORG, OTHER_ACCOUNT)
    for account_id in (ACCOUNT, SIBLING_ACCOUNT, OTHER_ACCOUNT):
        neo4j_session.run(
            """
            MATCH (a:AWSAccount{id: $account_id})
            MERGE (a)-[:RESOURCE]->(k:EC2KeyPair{id: $arn})
            SET k.arn = $arn, k.keyfingerprint = $fingerprint
            """,
            account_id=account_id, arn=_key(account_id), fingerprint=FINGERPRINT,
        )


def _flagged(neo4j_session):
    return {
        r['id'] for r in neo4j_session.run(
            "MATCH (k:EC2KeyPair{duplicate_keyfingerprint: true}) WHERE k.id CONTAINS ':kp-' RETURN k.id AS id",
        )
    }


def _matches(neo4j_session):
    return {
        frozenset((r['a'], r['b'])) for r in neo4j_session.run(
            "MATCH (a:EC2KeyPair)-[:MATCHING_FINGERPRINT]->(b:EC2KeyPair) "
            "WHERE a.id CONTAINS ':kp-' RETURN a.id AS a, b.id AS b",
        )
    }


def test_keypair_duplicate_fingerprints_stay_in_the_workspace(neo4j_session):
    _seed(neo4j_session)

    run_analysis_job(
        'aws_ec2_keypair_analysis.json', neo4j_session,
        exposure_job_parameters(WORKSPACE, ORG, ACCOUNT, TEST_UPDATE_TAG),
    )

    # The account's run flags its own key only; the sibling account's run flags the sibling's.
    assert _flagged(neo4j_session) == {_key(ACCOUNT)}
    assert _matches(neo4j_session) == {frozenset((_key(ACCOUNT), _key(SIBLING_ACCOUNT)))}

    run_analysis_job(
        'aws_ec2_keypair_analysis.json', neo4j_session,
        exposure_job_parameters(WORKSPACE, ORG, SIBLING_ACCOUNT, TEST_UPDATE_TAG),
    )

    assert _flagged(neo4j_session) == {_key(ACCOUNT), _key(SIBLING_ACCOUNT)}
    assert _matches(neo4j_session) == {frozenset((_key(ACCOUNT), _key(SIBLING_ACCOUNT)))}
