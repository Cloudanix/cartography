"""ELBv2 security group, target instance, listener and subnet links stay inside the tenant."""
from cartography.intel.aws.ec2 import load_balancer_v2s
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
# OWN and SIBLING belong to one workspace, OTHER to another customer.
OWN, SIBLING, OTHER = 'lb2-own', 'lb2-sibling', 'lb2-other'
WORKSPACE = 'lb2-ws'
OTHER_LB = 'other-alb.us-east-1.elb.amazonaws.com'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, WORKSPACE, 'lb2-org', OWN)
    create_test_org_account(neo4j_session, WORKSPACE, 'lb2-org', SIBLING)
    create_test_org_account(neo4j_session, 'lb2-ws-other', 'lb2-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (sibling:AWSAccount{id: $sibling}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:EC2SecurityGroup{groupid: 'sg-lb2-own'})
        MERGE (own)-[:RESOURCE]->(:EC2Instance{instanceid: 'i-lb2-own'})
        // a group the VPC owner shares with this account (VPC sharing)
        MERGE (sibling)-[:RESOURCE]->(:EC2SecurityGroup{groupid: 'sg-lb2-sibling'})
        MERGE (other)-[:RESOURCE]->(:EC2SecurityGroup{groupid: 'sg-lb2-other'})
        MERGE (other)-[:RESOURCE]->(:EC2Instance{instanceid: 'i-lb2-other'})
        MERGE (other)-[:RESOURCE]->(:LoadBalancerV2{id: $other_lb})
        """,
        own=OWN, sibling=SIBLING, other=OTHER, other_lb=OTHER_LB,
    )


def test_load_balancer_links_stay_in_the_workspace(neo4j_session):
    _seed(neo4j_session)
    lb = {
        'LoadBalancerArn': f'arn:aws:elasticloadbalancing:{REGION}:{OWN}:loadbalancer/app/web/abc',
        'DNSName': 'own-alb.us-east-1.elb.amazonaws.com', 'LoadBalancerName': 'web', 'CreatedTime': 'd',
        'region': REGION, 'AvailabilityZones': [],
        'SecurityGroups': ['sg-lb2-own', 'sg-lb2-sibling', 'sg-lb2-other'],
        'TargetGroups': [{
            'TargetType': 'instance', 'TargetGroupArn': 'arn:tg/1', 'Port': 80, 'Protocol': 'HTTP',
            'Targets': ['i-lb2-own', 'i-lb2-other'],
        }],
    }

    load_balancer_v2s.load_load_balancer_v2s(neo4j_session, [lb], OWN, TAG, REGION, WORKSPACE)
    # rows naming another customer's load balancer
    load_balancer_v2s.load_load_balancer_v2_listeners(
        neo4j_session, OTHER_LB, [{'ListenerArn': 'arn:listener/stray', 'Port': 443}], OWN, TAG,
    )
    load_balancer_v2s.load_load_balancer_v2_subnets(
        neo4j_session, OTHER_LB, [{'SubnetId': 'subnet-x'}], REGION, OWN, TAG,
    )

    groups = neo4j_session.run(
        "MATCH (:LoadBalancerV2)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(g:EC2SecurityGroup) RETURN g.groupid AS g",
    )
    assert {r['g'] for r in groups} == {'sg-lb2-own', 'sg-lb2-sibling'}
    exposed = neo4j_session.run("MATCH (:LoadBalancerV2)-[:EXPOSE]->(i:EC2Instance) RETURN i.instanceid AS i")
    assert [r['i'] for r in exposed] == ['i-lb2-own']
    claims = neo4j_session.run(
        "MATCH (a:AWSAccount)-[:RESOURCE]->(:EC2Instance{instanceid: 'i-lb2-other'}) RETURN a.id AS a",
    )
    assert [r['a'] for r in claims] == [OTHER]
    other_lb = neo4j_session.run(
        "MATCH (lb:LoadBalancerV2{id: $id}) RETURN size([(lb)-->(n) WHERE NOT n:AWSAccount | n]) AS out",
        id=OTHER_LB,
    ).single()
    assert other_lb['out'] == 0
