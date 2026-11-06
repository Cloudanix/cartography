import json

import cartography.intel.aws.dms
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters
from tests.integration.cartography.intel.aws.test_dms import _instance

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777794'
OTHER_ACCOUNT_ID = '888888888894'


def _security_group(neo4j_session, account_id, sg_id, ranges):
    """An SG with one inbound rule per CIDR, stored as security_groups.py does (IpRange / Ipv6Range by range)."""
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        MERGE (a)-[:RESOURCE]->(sg:EC2SecurityGroup{id: $sg_id})
        WITH sg
        UNWIND $ranges AS cidr
            MERGE (rule:IpPermissionInbound{ruleid: $sg_id + '/tcp/5432/' + cidr})
            SET rule.protocol = 'tcp', rule.fromport = 5432, rule.toport = 5432
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


def test_dms_instance_public_when_publicly_accessible_and_reachable(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-dmsx', 'o-dmsx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-dmsx-other', 'o-dmsx-other', OTHER_ACCOUNT_ID)
    _security_group(neo4j_session, ACCOUNT_ID, 'sg-dmsx-open4', ['0.0.0.0/0'])
    _security_group(neo4j_session, ACCOUNT_ID, 'sg-dmsx-open6', ['::/0'])
    _security_group(neo4j_session, ACCOUNT_ID, 'sg-dmsx-office', ['203.0.113.0/24'])
    _security_group(neo4j_session, OTHER_ACCOUNT_ID, 'sg-dmsx-other-open', ['0.0.0.0/0'])
    public = {'publiclyAccessible': True, 'publicIpAddresses': ['54.1.1.1']}
    cartography.intel.aws.dms.load_replication_instances(
        neo4j_session, [
            _instance(ACCOUNT_ID, 'dmsx-open4', securityGroupIds=['sg-dmsx-office', 'sg-dmsx-open4'], **public),
            _instance(ACCOUNT_ID, 'dmsx-open6', securityGroupIds=['sg-dmsx-open6'], **public),
            _instance(ACCOUNT_ID, 'dmsx-office', securityGroupIds=['sg-dmsx-office'], **public),
            _instance(ACCOUNT_ID, 'dmsx-sg-missing', securityGroupIds=['sg-dmsx-office', 'sg-dmsx-gone'], **public),
            _instance(ACCOUNT_ID, 'dmsx-no-sg', securityGroupIds=[], **public),
            _instance(ACCOUNT_ID, 'dmsx-private-open', securityGroupIds=['sg-dmsx-open4'], publiclyAccessible=False),
            _instance(ACCOUNT_ID, 'dmsx-closed-since', securityGroupIds=['sg-dmsx-office'], publiclyAccessible=False),
        ], ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.dms.load_replication_instances(
        neo4j_session, [_instance(OTHER_ACCOUNT_ID, 'dmsx-other', securityGroupIds=['sg-dmsx-other-open'], **public)],
        OTHER_ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    neo4j_session.run(
        "MATCH (n:DMSReplicationInstance{replication_instance_identifier: 'dmsx-closed-since'}) "
        "SET n.exposed_internet = true, n.exposed_internet_type = ['publicly_accessible_open_sg'], "
        "n.publicContext = '[]'",
    )
    params = exposure_job_parameters('ws-dmsx', 'o-dmsx', ACCOUNT_ID, TEST_UPDATE_TAG)
    cartography.intel.aws.dms.link_replication_instance_networks(neo4j_session, params)
    cartography.intel.aws.dms.link_replication_instance_networks(
        neo4j_session, exposure_job_parameters('ws-dmsx-other', 'o-dmsx-other', OTHER_ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    run_analysis_job('aws_dms_asset_exposure.json', neo4j_session, params)

    rows = neo4j_session.run(
        "MATCH (n:DMSReplicationInstance) RETURN n.replication_instance_identifier AS name, "
        "n.exposed_internet AS exposed, n.exposed_internet_type AS types, n.publicContext AS context",
    )
    instances = {r['name']: r for r in rows if r['name'].startswith('dmsx-')}
    assert {n: r['types'] for n, r in instances.items() if r['exposed']} == {
        'dmsx-open4': ['publicly_accessible_open_sg'],
        'dmsx-open6': ['publicly_accessible_open_sg'],
        'dmsx-sg-missing': ['publicly_accessible_sg_unresolved'],
        'dmsx-no-sg': ['publicly_accessible_sg_unresolved'],
    }
    assert instances['dmsx-closed-since']['context'] is None
    # Other tenant: never evaluated by this account's run.
    assert instances['dmsx-other']['exposed'] is None

    context = json.loads(instances['dmsx-open4']['context'])[0]
    assert (context['resource'], context['resourceType']) == (
        f'arn:aws:dms:us-east-1:{ACCOUNT_ID}:rep:dmsx-open4', 'aws-database-dms-replication-instance',
    )
    detail = context['context'][0]
    assert (detail['replicationInstanceIdentifier'], detail['publicIpAddresses']) == ('dmsx-open4', ['54.1.1.1'])
    assert detail['securityRules'] == [
        {
            'securityGroupId': 'sg-dmsx-open4', 'protocol': 'tcp', 'fromPort': 5432, 'toPort': 5432,
            'ipRange': '0.0.0.0/0',
        },
    ]
    missing = json.loads(instances['dmsx-sg-missing']['context'])[0]['context'][0]
    assert missing['unresolvedSecurityGroupIds'] == ['sg-dmsx-gone']
