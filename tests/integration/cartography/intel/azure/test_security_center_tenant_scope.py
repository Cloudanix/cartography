from cartography.intel.azure import securitycenter
from tests.integration.cartography.intel.azure.tenant_scope import arm_id
from tests.integration.cartography.intel.azure.tenant_scope import resource_group_of
from tests.integration.cartography.intel.azure.tenant_scope import rg_id
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import seed_node
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

CONTACT_A = arm_id(SUB_A, 'Microsoft.Security/securityContacts/default')
CONTACT_B = arm_id(SUB_B, 'Microsoft.Security/securityContacts/default')
# An id the API returned while syncing SUB_A that names SUB_B: its subscription segment is not an anchor.
CONTACT_FOREIGN = arm_id(SUB_B, 'Microsoft.Security/securityContacts/foreign')


def test_security_contacts_join_only_the_syncing_subscriptions_resource_group(neo4j_session):
    seed_customers(neo4j_session)
    seed_node(neo4j_session, SUB_B, 'AzureSecurityContact', CONTACT_B)

    securitycenter.load_security_contacts(
        neo4j_session, SUB_A, [{'id': CONTACT_A, 'name': 'default'}, {'id': CONTACT_FOREIGN, 'name': 'foreign'}],
        UPDATE_TAG,
    )

    assert resource_group_of(neo4j_session, 'AzureSecurityContact', CONTACT_A) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureSecurityContact', CONTACT_FOREIGN) == {rg_id(SUB_A)}
    assert resource_group_of(neo4j_session, 'AzureSecurityContact', CONTACT_B) == set()
