from cartography.intel.gcp import compute
from cartography.intel.gcp import sql
from cartography.util import run_cleanup_job

# Two customers sync concurrently; the other one wrote the shared nodes last.
OWN_TAG, OTHER_TAG = 100, 200
# Google's load-balancer health-check range: every tenant with a load balancer allows it in a firewall.
HEALTH_CHECK_RANGE = '35.191.0.0/16'
SQL_ADDRESS = '34.1.2.3'


def _params(tenant, tag):
    return {
        'UPDATE_TAG': tag, 'WORKSPACE_ID': f'ws-snc-{tenant}', 'GCP_ORGANIZATION_ID': f'org-snc-{tenant}',
        'GCP_PROJECT_ID': f'proj-snc-{tenant}', 'LIMIT_SIZE': 1000,
    }


def _seed(neo4j_session, tenant, tag):
    params = _params(tenant, tag)
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:GCPOrganization{id: $GCP_ORGANIZATION_ID})
            -[:OWNER]->(p:GCPProject{id: $GCP_PROJECT_ID})
        MERGE (p)-[:RESOURCE]->(vpc:GCPVpc{id: $GCP_PROJECT_ID + '/vpc'})
        SET vpc.lastupdated = $UPDATE_TAG
        MERGE (vpc)-[r:RESOURCE]->(fw:GCPFirewall{id: $GCP_PROJECT_ID + '/fw'})
        SET fw.lastupdated = $UPDATE_TAG, r.lastupdated = $UPDATE_TAG
        MERGE (p)-[s:RESOURCE]->(i:GCPSQLInstance{id: $GCP_PROJECT_ID + '/sql'})
        SET i.lastupdated = $UPDATE_TAG, s.lastupdated = $UPDATE_TAG
        """,
        **params,
    )


def _sync(neo4j_session, tenant, tag, ranges, sql_addresses):
    _seed(neo4j_session, tenant, tag)
    project = _params(tenant, tag)['GCP_PROJECT_ID']
    compute._attach_firewall_public_ip_address(
        neo4j_session, [{'id': f'{project}/fw', 'sourceRanges': ranges}], tag,
    )
    sql.load_public_ip_address(
        neo4j_session,
        {'id': f'{project}/sql', 'ipAddresses': [{'type': 'PRIMARY', 'ipAddress': a} for a in sql_addresses]},
        project, tag,
    )


def _cleanup(neo4j_session, tenant, tag):
    for job in ('gcp_compute_firewall_cleanup.json', 'gcp_sql_cleanup.json'):
        run_cleanup_job(job, neo4j_session, _params(tenant, tag))


def _links(neo4j_session):
    rows = neo4j_session.run(
        "MATCH (n)-[:MEMBER_OF_PUBLIC_IP_ADDRESS]->(ip:GCPPublicIpAddress) RETURN n.id AS n, ip.ipAddress AS ip",
    )
    return {(r['n'], r['ip']) for r in rows}


def _addresses(neo4j_session):
    return {r['ip'] for r in neo4j_session.run("MATCH (ip:GCPPublicIpAddress) RETURN ip.ipAddress AS ip")}


def test_tenant_cleanup_keeps_shared_public_addresses_another_tenant_links(neo4j_session):
    # Same health-check range in both tenants' firewalls; the same address on both SQL instances (released
    # by one customer, reassigned to the other, before the first one's sync noticed).
    _sync(neo4j_session, 'a', OWN_TAG, [HEALTH_CHECK_RANGE], [SQL_ADDRESS])
    _sync(neo4j_session, 'b', OTHER_TAG, [HEALTH_CHECK_RANGE], [SQL_ADDRESS])

    # Tenant a's sync, which loaded before b's, cleans up after it: its own edges are current.
    _cleanup(neo4j_session, 'a', OWN_TAG)
    assert _links(neo4j_session) == {
        (f'proj-snc-{t}/{kind}', ip)
        for t in 'ab' for kind, ip in (('fw', HEALTH_CHECK_RANGE), ('sql', SQL_ADDRESS))
    }

    # Tenant a no longer allows the range nor holds the address: only its own edges go.
    _sync(neo4j_session, 'a', OWN_TAG + 1, [], [])
    _cleanup(neo4j_session, 'a', OWN_TAG + 1)
    assert _links(neo4j_session) == {('proj-snc-b/fw', HEALTH_CHECK_RANGE), ('proj-snc-b/sql', SQL_ADDRESS)}
    assert _addresses(neo4j_session) == {HEALTH_CHECK_RANGE, SQL_ADDRESS}

    # Once no tenant links them, the orphan sweep deletes the shared nodes.
    _sync(neo4j_session, 'b', OTHER_TAG + 1, [], [])
    _cleanup(neo4j_session, 'b', OTHER_TAG + 1)
    assert _links(neo4j_session) == set()
    assert _addresses(neo4j_session) == set()


def _grant_domain(neo4j_session, tenant, tag, domain):
    # What iam.attach_*_role_to_domain leaves: the shared domain node, stamped by the last writer, and the
    # project's RESOURCE edge to it.
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $GCP_PROJECT_ID})
        MERGE (d:GCPDomain:GCPPrincipal{id: $domain}) SET d.name = $domain, d.lastupdated = $UPDATE_TAG
        MERGE (p)-[r:RESOURCE]->(d) SET r.lastupdated = $UPDATE_TAG
        """,
        domain=domain, **_params(tenant, tag),
    )


def _domain_owners(neo4j_session, domain):
    rows = neo4j_session.run(
        "MATCH (d:GCPDomain{id: $d}) OPTIONAL MATCH (p:GCPProject)-[:RESOURCE]->(d) RETURN p.id AS p", d=domain,
    )
    return {r['p'] for r in rows}


def test_domain_cleanup_keeps_a_domain_another_tenant_grants(neo4j_session):
    domain = 'partner-snc.example'
    for tenant, tag in (('a', OWN_TAG), ('b', OTHER_TAG)):
        _seed(neo4j_session, tenant, tag)
        _grant_domain(neo4j_session, tenant, tag, domain)

    run_cleanup_job('gcp_iam_domains_cleanup.json', neo4j_session, _params('a', OWN_TAG))
    assert _domain_owners(neo4j_session, domain) == {'proj-snc-a', 'proj-snc-b'}

    # Tenant a revoked the grant: its edge goes, the domain stays for tenant b.
    run_cleanup_job('gcp_iam_domains_cleanup.json', neo4j_session, _params('a', OWN_TAG + 1))
    assert _domain_owners(neo4j_session, domain) == {'proj-snc-b'}

    run_cleanup_job('gcp_iam_domains_cleanup.json', neo4j_session, _params('b', OTHER_TAG + 1))
    assert _domain_owners(neo4j_session, domain) == set()
