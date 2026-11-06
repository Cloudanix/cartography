"""IAM group memberships and policy statements stay inside the tenant."""
from cartography.intel.aws import iam
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
OWN, OTHER = '111100003333', '222200004444'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, 'iaml-ws-own', 'iaml-org-own', OWN)
    create_test_org_account(neo4j_session, 'iaml-ws-other', 'iaml-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:AWSGroup:AWSPrincipal{arn: 'g-own'})
        MERGE (own)-[:RESOURCE]->(uo:AWSUser:AWSPrincipal{arn: 'u-own'})
        MERGE (other)-[:RESOURCE]->(:AWSGroup:AWSPrincipal{arn: 'g-other'})
        MERGE (other)-[:RESOURCE]->(ux:AWSUser:AWSPrincipal{arn: 'u-other'})
        MERGE (uo)-[:POLICY]->(:AWSPolicy{id: 'p-own'})
        MERGE (ux)-[:POLICY]->(:AWSPolicy{id: 'p-other'})
        // an AWS-managed policy: one node, attached in both tenants
        MERGE (shared:AWSPolicy{id: 'arn:aws:iam::aws:policy/ReadOnlyAccess'})
        MERGE (uo)-[:POLICY]->(shared)
        MERGE (ux)-[:POLICY]->(shared)
        """,
        own=OWN, other=OTHER,
    )


def test_group_memberships_stay_in_the_account(neo4j_session):
    _seed(neo4j_session)

    iam.load_group_memberships(
        neo4j_session,
        {'g-own': {'Users': [{'Arn': 'u-own'}, {'Arn': 'u-other'}]}, 'g-other': {'Users': [{'Arn': 'u-own'}]}},
        OWN, TAG,
    )

    members = neo4j_session.run("MATCH (u)-[:MEMBER_AWS_GROUP]->(g) RETURN u.arn AS u, g.arn AS g")
    assert {(r['u'], r['g']) for r in members} == {('u-own', 'g-own')}


def test_policy_statements_are_written_only_for_policies_attached_in_the_tenant(neo4j_session):
    _seed(neo4j_session)
    policies = ('p-own', 'p-other', 'arn:aws:iam::aws:policy/ReadOnlyAccess')

    iam._batch_load_policy_statements(
        neo4j_session,
        [{'policy_id': p, 'statements': [{'id': f'{p}/statement/1', 'Effect': 'Allow'}]} for p in policies],
        OWN, TAG,
    )

    written = neo4j_session.run("MATCH (p:AWSPolicy)-[:STATEMENT]->(:AWSPolicyStatement) RETURN p.id AS p")
    assert {r['p'] for r in written} == {'p-own', 'arn:aws:iam::aws:policy/ReadOnlyAccess'}
