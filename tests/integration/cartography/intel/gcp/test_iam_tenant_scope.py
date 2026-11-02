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
