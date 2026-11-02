from cartography.intel.azure import iam
from tests.integration.cartography.intel.azure.tenant_scope import CUSTOMERS
from tests.integration.cartography.intel.azure.tenant_scope import linked_ids
from tests.integration.cartography.intel.azure.tenant_scope import seed_customers
from tests.integration.cartography.intel.azure.tenant_scope import SUB_A
from tests.integration.cartography.intel.azure.tenant_scope import SUB_B
from tests.integration.cartography.intel.azure.tenant_scope import UPDATE_TAG

TENANT_A = CUSTOMERS[SUB_A][1]
TENANT_B = CUSTOMERS[SUB_B][1]
# The same object id in both directories, so only the tenant anchor can tell the two principals apart.
SHARED_OID = 'oid-shared'


def _sp(tenant, oid):
    return {'id': f'tenants/{tenant}/ServiceAccounts/{oid}', 'object_id': oid, 'display_name': oid}


def _group(tenant, name):
    return {'id': f'tenants/{tenant}/Groups/{name}', 'object_id': name, 'display_name': name}


def _role(sub, name):
    return {'id': f'/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions/{name}', 'roleName': name}


def _seed(neo4j_session):
    seed_customers(neo4j_session)
    for tenant, sub in ((TENANT_A, SUB_A), (TENANT_B, SUB_B)):
        iam.load_tenant_service_accounts(neo4j_session, tenant, [_sp(tenant, SHARED_OID)], UPDATE_TAG)
        iam.load_tenant_groups(neo4j_session, tenant, [_group(tenant, 'admins')], UPDATE_TAG)
        iam.load_roles(neo4j_session, tenant, [_role(sub, 'reader')], [], UPDATE_TAG, sub)


def test_group_memberships_stay_in_the_syncing_tenant(neo4j_session):
    _seed(neo4j_session)

    iam.load_group_memberships(
        neo4j_session, TENANT_A,
        [
            {'group_id': _group(TENANT_A, 'admins')['id'], 'id': SHARED_OID},
            {'group_id': _group(TENANT_B, 'admins')['id'], 'id': SHARED_OID},
        ],
        UPDATE_TAG,
    )

    def members(tenant):
        group_id = _group(tenant, 'admins')['id']
        return linked_ids(neo4j_session, 'AzureGroup', group_id, 'MEMBER_AZURE_GROUP', 'AzurePrincipal')

    assert members(TENANT_A) == {_sp(TENANT_A, SHARED_OID)['id']}
    assert members(TENANT_B) == set()


def test_role_assignments_stay_in_the_syncing_tenant(neo4j_session):
    _seed(neo4j_session)
    assignments = [
        {'role_definition_id': _role(SUB_A, 'reader')['id'], 'principal_id': SHARED_OID, 'principal_type': 'User'},
        {'role_definition_id': _role(SUB_B, 'reader')['id'], 'principal_id': SHARED_OID, 'principal_type': 'User'},
    ]

    iam.load_roles(neo4j_session, TENANT_A, [_role(SUB_A, 'reader')], assignments, UPDATE_TAG, SUB_A)

    def linked(sub, rel, label):
        return linked_ids(neo4j_session, 'AzureRole', _role(sub, 'reader')['id'], rel, label)

    assert linked(SUB_A, 'ASSUME_ROLE', 'AzurePrincipal') == {_sp(TENANT_A, SHARED_OID)['id']}
    assert linked(SUB_B, 'ASSUME_ROLE', 'AzurePrincipal') == set()
    # The role reaches only the syncing tenant's subscription.
    assert linked(SUB_A, 'HAS_ACCESS', 'AzureSubscription') == {SUB_A}
