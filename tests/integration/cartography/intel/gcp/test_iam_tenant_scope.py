from cartography.intel.gcp import apigateway
from cartography.intel.gcp import iam

TEST_UPDATE_TAG = 123456789
# Two customers, each a workspace -> organization -> project chain.
TENANT, OTHER_TENANT = 'a', 'b'


def _params(tenant):
    return {
        'UPDATE_TAG': TEST_UPDATE_TAG, 'WORKSPACE_ID': f'ws-iamt-{tenant}', 'GCP_ORGANIZATION_ID': f'org-iamt-{tenant}',
        'GCP_PROJECT_ID': f'proj-iamt-{tenant}', 'LIMIT_SIZE': 1000,
    }


def _seed(neo4j_session):
    for tenant in (TENANT, OTHER_TENANT):
        params = _params(tenant)
        neo4j_session.run(
            """
            MERGE (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(org:GCPOrganization{id: $GCP_ORGANIZATION_ID})
                -[:OWNER]->(:GCPProject{id: $GCP_PROJECT_ID})
            MERGE (org)-[:RESOURCE]->(:GCPRole{id: $GCP_ORGANIZATION_ID + '/roles/viewer', name: 'roles/viewer'})
            """,
            **params,
        )


def _rows(neo4j_session, query, **kwargs):
    return {tuple(r.values()) for r in neo4j_session.run(query, **kwargs)}


def _bind(neo4j_session, tenant, members, role='roles/viewer'):
    params = _params(tenant)
    parent_id = f"projects/{params['GCP_PROJECT_ID']}"
    bindings = [{'role': role, 'members': members, 'parent': 'project', 'parent_id': parent_id}]
    iam.load_bindings(
        neo4j_session, bindings, params['GCP_PROJECT_ID'], params['GCP_ORGANIZATION_ID'], TEST_UPDATE_TAG, params,
    )


def test_organization_domains_are_the_syncing_orgs_only(neo4j_session):
    _seed(neo4j_session)
    # The other customer granted its partner's domain a role; this customer's project holds its own domain.
    _bind(neo4j_session, OTHER_TENANT, ['domain:partner-iamt.example'])
    neo4j_session.run(
        "MATCH (p:GCPProject{id: $p}) MERGE (p)-[:RESOURCE]->(:GCPDomain:GCPPrincipal{id: $d, name: $d})",
        p=_params(TENANT)['GCP_PROJECT_ID'], d='a-iamt.example',
    )

    assert iam._get_organization_domains(neo4j_session, _params(TENANT)) == frozenset({'a-iamt.example'})

    # So a partner user in this customer's policy is third party, whatever other tenants granted.
    _bind(neo4j_session, TENANT, ['user:bob@partner-iamt.example', 'user:alice@a-iamt.example'])
    assert _rows(
        neo4j_session,
        "MATCH (:GCPRole{id: $role})-[:TRUSTS_GCP_PRINCIPAL]->(ep:GCPExternalPrincipal) RETURN ep.principal",
        role=f"{_params(TENANT)['GCP_ORGANIZATION_ID']}/roles/viewer",
    ) == {('user:bob@partner-iamt.example',)}


def _service_account(tenant):
    return f"svc@{_params(tenant)['GCP_PROJECT_ID']}.iam.gserviceaccount.com"


def test_binding_to_another_tenants_service_account_writes_nothing_on_it(neo4j_session):
    _seed(neo4j_session)
    for tenant in (TENANT, OTHER_TENANT):
        email = _service_account(tenant)
        iam.load_service_accounts(
            neo4j_session, [{'id': email, 'email': email, 'name': email, 'displayName': 'svc'}],
            _params(tenant)['GCP_PROJECT_ID'], TEST_UPDATE_TAG,
        )
    project = _params(TENANT)['GCP_PROJECT_ID']
    custom_role = f'projects/{project}/roles/custom'
    neo4j_session.run(
        "MATCH (p:GCPProject{id: $p}) MERGE (p)-[:RESOURCE]->(:GCPRole{id: $r})", p=project, r=custom_role,
    )
    members = [f'serviceAccount:{_service_account(TENANT)}', f'serviceAccount:{_service_account(OTHER_TENANT)}']

    # This customer grants a predefined and a project custom role to its own and the other customer's SA.
    _bind(neo4j_session, TENANT, members)
    _bind(neo4j_session, TENANT, members, role=custom_role)

    assert _rows(
        neo4j_session,
        "MATCH (sa:GCPServiceAccount)-[:ASSUME_ROLE]->(r:GCPRole) WHERE sa.id IN $sas RETURN sa.id, r.id",
        sas=[_service_account(TENANT), _service_account(OTHER_TENANT)],
    ) == {
        (_service_account(TENANT), f"{_params(TENANT)['GCP_ORGANIZATION_ID']}/roles/viewer"),
        (_service_account(TENANT), custom_role),
    }
    assert _rows(
        neo4j_session, "MATCH (sa:GCPServiceAccount{id: $sa}) RETURN sa.isDeleted", sa=_service_account(OTHER_TENANT),
    ) == {(None,)}
    # The grant to the foreign SA is still visible to this customer, as an external principal.
    assert (f'serviceAccount:{_service_account(OTHER_TENANT)}',) in _rows(
        neo4j_session,
        "MATCH (:GCPRole{id: $r})-[:TRUSTS_GCP_PRINCIPAL]->(ep:GCPExternalPrincipal) RETURN ep.principal",
        r=custom_role,
    )


def test_shared_principals_keep_tenant_facts_on_the_tenants_edges(neo4j_session):
    _seed(neo4j_session)
    # A consultant both customers grant a role to: one GCPUser node for both tenants.
    for tenant in (TENANT, OTHER_TENANT):
        _bind(neo4j_session, tenant, ['user:consultant@shared-iamt.example'])

    # The console link names a project, so it is per tenant and lives on the tenant's edge.
    assert _rows(
        neo4j_session,
        """
        MATCH (org:GCPOrganization)-[r:RESOURCE]->(u:GCPUser{id: 'consultant@shared-iamt.example'})
        RETURN org.id, r.consolelink CONTAINS ('project=proj-iamt-' + right(org.id, 1)), u.consolelink
        """,
    ) == {
        (_params(TENANT)['GCP_ORGANIZATION_ID'], True, None),
        (_params(OTHER_TENANT)['GCP_ORGANIZATION_ID'], True, None),
    }


def test_shared_external_principal_keeps_the_granting_project_on_the_edge(neo4j_session):
    _seed(neo4j_session)
    for tenant in (TENANT, OTHER_TENANT):
        _bind(neo4j_session, tenant, ['user:bob@vendor-iamt.example'])

    # The granting project is on each tenant's trust edge, never on the shared external principal.
    assert _rows(
        neo4j_session,
        """
        MATCH (role:GCPRole)-[r:TRUSTS_GCP_PRINCIPAL]->(ep:GCPExternalPrincipal)
        WHERE ep.principal = 'user:bob@vendor-iamt.example'
        RETURN role.id, r.account_id, r.access_type, ep.account_id
        """,
    ) == {
        (f"{_params(t)['GCP_ORGANIZATION_ID']}/roles/viewer", _params(t)['GCP_PROJECT_ID'], 'ThirdParty', None)
        for t in (TENANT, OTHER_TENANT)
    }


def test_policy_members_link_only_the_orgs_own_principals(neo4j_session):
    _seed(neo4j_session)
    for tenant in (TENANT, OTHER_TENANT):
        email = _service_account(tenant)
        iam.load_service_accounts(
            neo4j_session, [{'id': email, 'email': email, 'name': email, 'displayName': 'svc'}],
            _params(tenant)['GCP_PROJECT_ID'], TEST_UPDATE_TAG,
        )
    api_id = 'projects/proj-iamt-a/locations/global/apis/api-iamt'
    neo4j_session.run("MERGE (:GCPAPI{id: $id})", id=api_id)
    # This customer's API policy names its own service account and the other customer's.
    api = {'id': api_id, 'entities': [{'email': _service_account(TENANT)}, {'email': _service_account(OTHER_TENANT)}]}

    apigateway.load_apis_entity_relation(neo4j_session, api, TEST_UPDATE_TAG, _params(TENANT))

    assert _rows(
        neo4j_session, "MATCH (p:GCPPrincipal)-[:USES]->(:GCPAPI{id: $id}) RETURN p.id", id=api_id,
    ) == {(_service_account(TENANT),)}
