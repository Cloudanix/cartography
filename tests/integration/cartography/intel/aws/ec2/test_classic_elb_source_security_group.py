import cartography.intel.aws.ec2.load_balancers
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777798'
OTHER_ACCOUNT_ID = '888888888898'


def _default_group(neo4j_session, account_id, vpc_id, group_id):
    # Every VPC has a security group named "default"; names repeat across VPCs and tenants.
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (aa)-[:RESOURCE]->(sg:EC2SecurityGroup{id: $group_id})
        SET sg.groupid = $group_id, sg.name = 'default'
        MERGE (aa)-[:RESOURCE]->(vpc:AWSVpc{id: $vpc_id})
        MERGE (vpc)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        """,
        account_id=account_id, vpc_id=vpc_id, group_id=group_id,
    )


def _classic_elb(name, vpc_id):
    return {
        'DNSName': f'{name}.us-east-1.elb.amazonaws.com',
        'LoadBalancerName': name,
        'CreatedTime': '2019-10-27 00:35:00',
        'Scheme': 'internet-facing',
        'region': 'us-east-1',
        'VPCId': vpc_id,
        'Subnets': [],
        'SecurityGroups': [],
        'SourceSecurityGroup': {'OwnerAlias': ACCOUNT_ID, 'GroupName': 'default'},
        'Instances': [],
        'ListenerDescriptions': [],
    }


def _source_groups(neo4j_session, elb_name):
    rows = neo4j_session.run(
        "MATCH (elb:LoadBalancer{name: $name})-[:SOURCE_SECURITY_GROUP]->(sg:EC2SecurityGroup) RETURN sg.id AS id",
        name=elb_name,
    )
    return {row['id'] for row in rows}


def test_classic_elb_source_security_group_stays_in_its_own_account_and_vpc(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-ssg', 'o-ssg', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-ssg-other', 'o-ssg-other', OTHER_ACCOUNT_ID)
    _default_group(neo4j_session, ACCOUNT_ID, 'vpc-ssg-a', 'sg-ssg-a')
    _default_group(neo4j_session, ACCOUNT_ID, 'vpc-ssg-b', 'sg-ssg-b')
    _default_group(neo4j_session, OTHER_ACCOUNT_ID, 'vpc-ssg-other', 'sg-ssg-other')

    cartography.intel.aws.ec2.load_balancers.load_load_balancers(
        neo4j_session,
        [_classic_elb('ssg-elb', 'vpc-ssg-a'), _classic_elb('ssg-elb-novpc', None)],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    # Only the "default" group of the load balancer's own VPC: never another VPC's, never another tenant's.
    assert _source_groups(neo4j_session, 'ssg-elb') == {'sg-ssg-a'}
    # Without a VPC (EC2-Classic) the name cannot be resolved to one group, so no edge.
    assert _source_groups(neo4j_session, 'ssg-elb-novpc') == set()
