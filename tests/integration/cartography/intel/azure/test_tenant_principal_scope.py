from cartography.intel.azure import tenant

TEST_UPDATE_TAG = 123456789
# The same login connects two customers' tenants (a consultant's account, or a multi-tenant
# app whose client id is the "email"): its object id and display name differ per tenant.
SHARED_EMAIL = 'consultant@partner.example'
TENANTS = {
    'tenant-principal-1': ('ws-principal-1', 'object-id-in-tenant-1', 'Consultant (Tenant 1)'),
    'tenant-principal-2': ('ws-principal-2', 'object-id-in-tenant-2', 'Consultant (Tenant 2)'),
}


def _tenant_obj(tenant_id):
    return {
        'id': f'/tenants/{tenant_id}', 'tenantId': tenant_id, 'tenantCategory': 'Home', 'tenantType': 'AAD',
        'displayName': tenant_id, 'country': None, 'countryCode': None, 'defaultDomain': f'{tenant_id}.example',
    }


def test_connecting_principal_keeps_tenant_specific_facts_on_the_tenant_edge(neo4j_session):
    for tenant_id, (workspace_id, object_id, name) in TENANTS.items():
        tenant.load_azure_tenant(
            neo4j_session, _tenant_obj(tenant_id), {'email': SHARED_EMAIL, 'id': object_id, 'name': name},
            TEST_UPDATE_TAG, {'WORKSPACE_ID': workspace_id},
        )

    principal = neo4j_session.run(
        "MATCH (ap:AzurePrincipal{id: $email}) RETURN properties(ap) AS props", email=SHARED_EMAIL,
    ).single()['props']
    # The node is shared by both tenants: it holds no tenant's object id or name.
    assert 'userid' not in principal
    assert 'name' not in principal
    assert principal['email'] == SHARED_EMAIL

    rows = neo4j_session.run(
        """
        MATCH (at:AzureTenant)-[r:RESOURCE]->(:AzurePrincipal{id: $email})
        RETURN at.id AS tenant, r.userid AS userid, r.name AS name
        """,
        email=SHARED_EMAIL,
    )
    assert {row['tenant']: (row['userid'], row['name']) for row in rows} == {
        tenant_id: (object_id, name) for tenant_id, (_, object_id, name) in TENANTS.items()
    }
