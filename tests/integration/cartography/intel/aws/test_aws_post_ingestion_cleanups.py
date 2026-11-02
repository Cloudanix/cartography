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
    # This account's stale edge goes (zone-membership directions fixed); the other tenant's stays.
    assert sources == {'pd-a2-ns'}


def test_post_ingestion_principals_cleanup_spares_other_tenants_principals(neo4j_session):
    create_test_org_account(neo4j_session, 'pp-ws1', 'pp-o1', 'pp-a1')
    create_test_org_account(neo4j_session, 'pp-ws2', 'pp-o2', 'pp-b1')
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: 'pp-a1'}), (b:AWSAccount{id: 'pp-b1'})
        MERGE (a)-[:RESOURCE]->(ra:AWSRole:AWSPrincipal{arn: 'pp-role-a'}) SET ra.lastupdated = $tag
        MERGE (b)-[:RESOURCE]->(rb:AWSRole:AWSPrincipal{arn: 'pp-role-b'}) SET rb.lastupdated = 5
        // the other tenant's own user, synced with its own tag
        MERGE (b)-[:RESOURCE]->(:AWSUser:AWSPrincipal{arn: 'pp-user-b', lastupdated: 5})
        // outside principals: one only this account trusted (stale), one also trusted by the other tenant,
        // one this account still trusts
        MERGE (gone:AWSPrincipal{arn: 'pp-outside-gone', lastupdated: 1})
        MERGE (shared:AWSPrincipal{arn: 'pp-outside-shared', lastupdated: 5})
        MERGE (kept:AWSPrincipal{arn: 'pp-outside-kept', lastupdated: $tag})
        MERGE (ra)-[:TRUSTS_AWS_PRINCIPAL{lastupdated: 1}]->(gone)
        MERGE (ra)-[:TRUSTS_AWS_PRINCIPAL{lastupdated: 1}]->(shared)
        MERGE (rb)-[:TRUSTS_AWS_PRINCIPAL{lastupdated: 5}]->(shared)
        MERGE (ra)-[:TRUSTS_AWS_PRINCIPAL{lastupdated: $tag}]->(kept)
        """,
        tag=TEST_UPDATE_TAG,
    )

    _run(neo4j_session, 'aws_post_ingestion_principals_cleanup.json', 'pp-ws1', 'pp-o1', 'pp-a1')

    principals = {
        r['arn'] for r in neo4j_session.run(
            "MATCH (n:AWSPrincipal) WHERE n.arn STARTS WITH 'pp-' RETURN n.arn AS arn",
        )
    }
    assert principals == {'pp-role-a', 'pp-role-b', 'pp-user-b', 'pp-outside-shared', 'pp-outside-kept'}
    trusts = {
        (r['role'], r['principal']) for r in neo4j_session.run(
            "MATCH (r:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(p) WHERE r.arn STARTS WITH 'pp-' "
            "RETURN r.arn AS role, p.arn AS principal",
        )
    }
    assert trusts == {('pp-role-b', 'pp-outside-shared'), ('pp-role-a', 'pp-outside-kept')}
