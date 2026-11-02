"""
IAM lookups reach existing nodes only through the syncing tenancy (AGENTS.md "Tenant isolation").
Tenancy B already holds the group / user / policy / compartment an id in tenancy A's data points at.
"""
import pytest

from cartography.intel.oci import iam
from tests.integration.cartography.intel.oci.common import linked
from tests.integration.cartography.intel.oci.common import seed_tenancy

TAG = 7


@pytest.fixture
def tenants(neo4j_session):
    neo4j_session.run("MATCH (n) DETACH DELETE n")
    a, b = seed_tenancy(neo4j_session, 'iam-a'), seed_tenancy(neo4j_session, 'iam-b')
    for prefix, ids in (('iam-a', a), ('iam-b', b)):
        neo4j_session.run(
            """
            MATCH (t:OCITenancy{id: $tenancy})
            MERGE (t)-[:RESOURCE]->(:OCIGroup{id: $prefix + '-group'})
            MERGE (t)-[:RESOURCE]->(:OCIUser{id: $prefix + '-user'})
            MERGE (t)-[:RESOURCE]->(:OCIPolicy{id: $prefix + '-policy'})
            """,
            tenancy=ids['OCI_TENANCY_ID'], prefix=prefix,
        )
    return a, b


def test_group_memberships_stay_in_the_syncing_tenancy(neo4j_session, tenants):
    a, _ = tenants
    memberships = {
        'any': {
            'GroupMemberships': [
                {'group-id': 'iam-a-group', 'user-id': 'iam-a-user'},
                {'group-id': 'iam-b-group', 'user-id': 'iam-a-user'},
                {'group-id': 'iam-a-group', 'user-id': 'iam-b-user'},
            ],
        },
    }
    iam.load_group_memberships(neo4j_session, memberships, a['OCI_TENANCY_ID'], TAG)
    assert linked(neo4j_session, 'iam-a-user', 'MEMBER_OCID_GROUP', 'iam-a-group')
    assert not linked(neo4j_session, 'iam-a-user', 'MEMBER_OCID_GROUP', 'iam-b-group')
    assert not linked(neo4j_session, 'iam-b-user', 'MEMBER_OCID_GROUP', 'iam-a-group')


def test_policy_references_stay_in_the_syncing_tenancy(neo4j_session, tenants):
    a, b = tenants
    tenancy = a['OCI_TENANCY_ID']
    iam.load_oci_policy_group_reference(neo4j_session, 'iam-a-policy', 'iam-a-group', tenancy, TAG)
    iam.load_oci_policy_group_reference(neo4j_session, 'iam-a-policy', 'iam-b-group', tenancy, TAG)
    iam.load_oci_policy_group_reference(neo4j_session, 'iam-b-policy', 'iam-a-group', tenancy, TAG)
    iam.load_oci_policy_compartment_reference(neo4j_session, 'iam-a-policy', a['OCI_COMPARTMENT_ID'], tenancy, TAG)
    iam.load_oci_policy_compartment_reference(neo4j_session, 'iam-a-policy', b['OCI_COMPARTMENT_ID'], tenancy, TAG)

    assert linked(neo4j_session, 'iam-a-policy', 'OCI_POLICY_REFERENCE', 'iam-a-group')
    assert linked(neo4j_session, 'iam-a-policy', 'OCI_POLICY_REFERENCE', a['OCI_COMPARTMENT_ID'])
    assert not linked(neo4j_session, 'iam-a-policy', 'OCI_POLICY_REFERENCE', 'iam-b-group')
    assert not linked(neo4j_session, 'iam-b-policy', 'OCI_POLICY_REFERENCE', 'iam-a-group')
    assert not linked(neo4j_session, 'iam-a-policy', 'OCI_POLICY_REFERENCE', b['OCI_COMPARTMENT_ID'])


def test_external_principal_trust_is_written_only_from_the_syncing_tenancys_policy(neo4j_session, tenants):
    a, _ = tenants
    principal = {'principal': 'ocid1.tenancy.oc1..vendor', 'access_type': 'ThirdParty', 'statement_verb': 'admit'}
    iam.load_oci_external_principal(neo4j_session, 'iam-a-policy', principal, a['OCI_TENANCY_ID'], TAG)
    iam.load_oci_external_principal(neo4j_session, 'iam-b-policy', principal, a['OCI_TENANCY_ID'], TAG)
    trusted = neo4j_session.run(
        "MATCH (p:OCIPolicy)-[:TRUSTS_OCI_PRINCIPAL]->(:OCIExternalPrincipal) RETURN collect(p.id) AS ids",
    ).single()['ids']
    assert trusted == ['iam-a-policy']
