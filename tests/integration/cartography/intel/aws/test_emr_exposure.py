import json

from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777773'
OTHER_ACCOUNT_ID = '888888888883'
PUBLIC_DNS = 'ec2-54-1-2-3.compute-1.amazonaws.com'


def _security_group(neo4j_session, account_id, sg_id, ranges):
    """An SG with one inbound rule per CIDR, stored as security_groups.py does (IpRange / Ipv6Range by range)."""
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        MERGE (a)-[:RESOURCE]->(sg:EC2SecurityGroup{id: $sg_id})
        WITH sg
        UNWIND $ranges AS cidr
            MERGE (rule:IpPermissionInbound{ruleid: $sg_id + '/tcp/22/' + cidr})
            SET rule.protocol = 'tcp', rule.fromport = 22, rule.toport = 22
            MERGE (rule)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
            WITH rule, cidr
            CALL apoc.merge.node(
                [CASE WHEN cidr CONTAINS ':' THEN 'Ipv6Range' ELSE 'IpRange' END],
                {id: 'IpRule/' + rule.ruleid + '/ipRange/' + cidr}, {range: cidr}
            ) YIELD node
            MERGE (node)-[:MEMBER_OF_IP_RULE]->(rule)
        """,
        account_id=account_id, sg_id=sg_id, ranges=ranges,
    )


def _cluster(neo4j_session, account_id, cluster_id, dns, sg_ids, **stale):
    # Properties as load_emr_clusters stores them.
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        MERGE (a)-[:RESOURCE]->(c:EMRCluster{id: $cluster_id})
        SET c.name = $cluster_id, c.master_public_dns_name = $dns, c.master_security_group_ids = $sg_ids,
            c.public_access_configuration = false
        SET c += $stale
        """,
        account_id=account_id, cluster_id=cluster_id, dns=dns, sg_ids=sg_ids, stale=stale,
    )


def test_emr_cluster_public_when_master_has_public_dns_and_open_security_group(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-emrx', 'o-emrx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-emrx-other', 'o-emrx-other', OTHER_ACCOUNT_ID)
    _security_group(neo4j_session, ACCOUNT_ID, 'sg-emrx-open', ['0.0.0.0/0'])
    _security_group(neo4j_session, ACCOUNT_ID, 'sg-emrx-open6', ['::/0'])
    _security_group(neo4j_session, ACCOUNT_ID, 'sg-emrx-office', ['203.0.113.0/24'])
    _security_group(neo4j_session, OTHER_ACCOUNT_ID, 'sg-emrx-other-open', ['0.0.0.0/0'])

    _cluster(neo4j_session, ACCOUNT_ID, 'j-open', PUBLIC_DNS, ['sg-emrx-office', 'sg-emrx-open'])
    _cluster(neo4j_session, ACCOUNT_ID, 'j-open-ipv6', PUBLIC_DNS, ['sg-emrx-open6'])
    _cluster(neo4j_session, ACCOUNT_ID, 'j-office-only', PUBLIC_DNS, ['sg-emrx-office'])
    # Private subnet: no public DNS, so an open SG does not reach it from the internet.
    _cluster(neo4j_session, ACCOUNT_ID, 'j-private-subnet', None, ['sg-emrx-open'])
    # Flagged by the old job (account Block Public Access off); must be cleared.
    _cluster(
        neo4j_session, ACCOUNT_ID, 'j-stale', None, [],
        anonymous_access=True, anonymous_access_type=['assign_public_ip'], publicContext='[]',
    )
    _cluster(neo4j_session, OTHER_ACCOUNT_ID, 'j-other', PUBLIC_DNS, ['sg-emrx-other-open'])

    run_analysis_job(
        'aws_emr_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-emrx', 'o-emrx', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        """
        MATCH (c:EMRCluster)
        RETURN c.id AS id, c.exposed_internet AS exposed, c.exposed_internet_type AS types,
               c.anonymous_access AS anonymous, c.anonymous_access_type AS anonymous_types, c.publicContext AS context
        """,
    )
    clusters = {r['id']: r for r in rows}
    assert {i for i, r in clusters.items() if r['exposed']} == {'j-open', 'j-open-ipv6'}
    assert clusters['j-open']['types'] == ['master_public_open_sg']
    context = json.loads(clusters['j-open']['context'])[0]['context'][0]
    assert context['masterPublicDnsName'] == PUBLIC_DNS
    assert [r['securityGroupId'] for r in context['securityRules']] == ['sg-emrx-open']
    stale = clusters['j-stale']
    assert (stale['anonymous'], stale['anonymous_types'], stale['context']) == (None, None, None)
    assert clusters['j-other']['exposed'] is None
