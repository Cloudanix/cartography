"""
Two customers for tenant-anchoring tests (AGENTS.md "Tenant isolation", rule 7).

Tenant a (workspace ws-ta-a) owns projects proj-ta-a and proj-ta-a2 in one organization; tenant b is another
customer with proj-ta-b. A test points tenant a's API data at a node only tenant b holds and asserts no edge
reaches it, next to the same link to tenant a's own node, which must still be made.
"""
TAG = 123456789
OWN, OWN_OTHER, FOREIGN = 'proj-ta-a', 'proj-ta-a2', 'proj-ta-b'


def tenant_params(tenant='a', project=None):
    return {
        'UPDATE_TAG': TAG, 'WORKSPACE_ID': f'ws-ta-{tenant}', 'GCP_ORGANIZATION_ID': f'organizations/ta-{tenant}',
        'GCP_PROJECT_ID': project or f'proj-ta-{tenant}', 'LIMIT_SIZE': 1000, 'service_labels': [],
    }


def seed_tenants(neo4j_session):
    # Production shape: CloudanixWorkspace-[:OWNER]->GCPOrganization-[:OWNER]->GCPProject.
    for tenant, projects in (('a', [OWN, OWN_OTHER]), ('b', [FOREIGN])):
        neo4j_session.run(
            """
            MERGE (w:CloudanixWorkspace{id: $WORKSPACE_ID})
            MERGE (w)-[:OWNER]->(o:GCPOrganization{id: $GCP_ORGANIZATION_ID})
            WITH o UNWIND $projects AS project
            MERGE (o)-[:OWNER]->(:GCPProject{id: project})
            """,
            projects=projects, **tenant_params(tenant),
        )


def put(neo4j_session, parent_label, parent_id, rel, label, node_id, **props):
    """MERGE (parent)-[rel]->(label{id: node_id}) and SET props on the node."""
    # Labels and relationship types cannot be parameters; every caller passes literals.
    neo4j_session.run(
        f"MATCH (p:{parent_label}{{id: $parent}}) MERGE (p)-[:{rel}]->(n:{label}{{id: $id}}) SET n += $props",
        parent=parent_id, id=node_id, props=props,
    )


def put_principal(neo4j_session, tenant, email):
    neo4j_session.run(
        "MATCH (o:GCPOrganization{id: $org}) MERGE (o)-[:RESOURCE]->(:GCPPrincipal{email: $email})",
        org=tenant_params(tenant)['GCP_ORGANIZATION_ID'], email=email,
    )


def sources(neo4j_session, rel, target_id):
    """Ids (or emails) of the nodes holding a rel edge into the node with id target_id."""
    rows = neo4j_session.run(
        f"MATCH (s)-[:{rel}]->(t{{id: $id}}) RETURN coalesce(s.id, s.email) AS s", id=target_id,
    )
    return {r['s'] for r in rows}


def targets(neo4j_session, source_id, rel):
    """Ids of the nodes the node with id source_id points at over rel."""
    rows = neo4j_session.run(f"MATCH (s{{id: $id}})-[:{rel}]->(t) RETURN t.id AS t", id=source_id)
    return {r['t'] for r in rows}
