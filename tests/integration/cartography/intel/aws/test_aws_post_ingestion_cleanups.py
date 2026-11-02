from importlib.resources import read_text

from cartography.graph.job import GraphJob
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
STALE_TAG = 1


def _run(neo4j_session, filename, workspace_id, org_id, account_id):
    # GraphJob directly, not run_cleanup_job: that one logs and swallows a failing statement.
    GraphJob.run_from_json(
        neo4j_session,
        read_text('cartography.data.jobs.cleanup', filename),
        {
            'WORKSPACE_ID': workspace_id, 'ORGANIZATION_ID': org_id, 'AWS_ID': account_id,
            'UPDATE_TAG': TEST_UPDATE_TAG, 'LIMIT_SIZE': 100,
        },
    )


def test_post_ingestion_dns_cleanup_runs_and_spares_other_tenants(neo4j_session):
    # Both tenants' NS records point at the same shared AWS name server. The job used to stop at a
    # Cypher syntax error (stray brace) in its NameServer statement.
    create_test_org_account(neo4j_session, 'pd-ws1', 'pd-o1', 'pd-a1')
    create_test_org_account(neo4j_session, 'pd-ws2', 'pd-o2', 'pd-a2')
    neo4j_session.run(
        """
        MERGE (ns:NameServer{id: 'pd-ns-1.awsdns-01.com'})
        WITH ns
        UNWIND ['pd-a1', 'pd-a2'] AS account_id
        MATCH (a:AWSAccount{id: account_id})
        MERGE (a)-[:RESOURCE]->(z:AWSDNSZone{zoneid: account_id + '-zone'})
        MERGE (z)<-[:MEMBER_OF_DNS_ZONE]-(r:AWSDNSRecord:DNSRecord{id: account_id + '-ns'})
        SET r.lastupdated = $tag
        MERGE (r)-[p:DNS_POINTS_TO]->(ns)
        SET p.lastupdated = $stale
        """,
        tag=TEST_UPDATE_TAG, stale=STALE_TAG,
    )

    _run(neo4j_session, 'aws_post_ingestion_dns_cleanup.json', 'pd-ws1', 'pd-o1', 'pd-a1')

    sources = {
        r['id'] for r in neo4j_session.run(
            "MATCH (r:AWSDNSRecord)-[:DNS_POINTS_TO]->(:NameServer{id: 'pd-ns-1.awsdns-01.com'}) RETURN r.id AS id",
        )
    }
    assert 'pd-a2-ns' in sources
