"""KMS aliases, grants and policy results reach only the syncing account's keys."""
from cartography.intel.aws import kms
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
OWN, OTHER = 'kms-own', 'kms-other'


def test_kms_details_stay_in_the_account(neo4j_session):
    create_test_org_account(neo4j_session, 'kms-ws-own', 'kms-org-own', OWN)
    create_test_org_account(neo4j_session, 'kms-ws-other', 'kms-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:KMSKey{id: 'key-own', name: 'key-own'})
        MERGE (other)-[:RESOURCE]->(:KMSKey{id: 'key-other', name: 'key-other'})
        """,
        own=OWN, other=OTHER,
    )

    kms._load_kms_key_aliases(
        neo4j_session,
        [{'AliasArn': f'alias/{key}', 'TargetKeyId': key, 'region': REGION} for key in ('key-own', 'key-other')],
        OWN, TAG,
    )
    kms._load_kms_key_grants(
        neo4j_session,
        [{'GrantId': f'grant-{key}', 'KeyId': key, 'CreationDate': 'd', 'region': REGION} for key in ('key-own', 'key-other')],
        OWN, TAG,
    )
    kms._load_kms_key_policies(
        neo4j_session,
        [
            {'kms_key': key, 'internet_accessible': True, 'accessible_actions': ['kms:*'], 'region': REGION}
            for key in ('key-own', 'key-other')
        ],
        OWN, TAG,
    )

    linked = neo4j_session.run(
        "MATCH (n)-[r:KNOWN_AS|APPLIED_ON]->(k:KMSKey) RETURN type(r) AS r, k.id AS k",
    )
    assert {(r['r'], r['k']) for r in linked} == {('KNOWN_AS', 'key-own'), ('APPLIED_ON', 'key-own')}
    public = neo4j_session.run("MATCH (k:KMSKey) WHERE k.anonymous_access RETURN k.id AS k")
    assert [r['k'] for r in public] == ['key-own']
