"""Classic ELB security group, subnet, target instance and listener links stay inside the tenant."""
from cartography.intel.aws.ec2 import load_balancers
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
# OWN and SIBLING belong to one workspace, OTHER to another customer.
OWN, SIBLING, OTHER = 'clb-own', 'clb-sibling', 'clb-other'
WORKSPACE = 'clb-ws'
OTHER_LB = 'other-clb.us-east-1.elb.amazonaws.com'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, WORKSPACE, 'clb-org', OWN)
    create_test_org_account(neo4j_session, WORKSPACE, 'clb-org', SIBLING)
    create_test_org_account(neo4j_session, 'clb-ws-other', 'clb-org-other', OTHER)
    neo4j_session.run(
        """
        UNWIND [$own, $sibling, $other] AS account_id
        MATCH (a:AWSAccount{id: account_id})
        MERGE (a)-[:RESOURCE]->(:EC2SecurityGroup{id: 'sg-' + account_id, groupid: 'sg-' + account_id})
        MERGE (a)-[:RESOURCE]->(:EC2Subnet{subnetid: 'subnet-' + account_id})
        MERGE (a)-[:RESOURCE]->(:EC2Instance{instanceid: 'i-' + account_id})
        WITH a WHERE a.id = $other
        MERGE (a)-[:RESOURCE]->(:LoadBalancer{id: $other_lb})
        """,
        own=OWN, sibling=SIBLING, other=OTHER, other_lb=OTHER_LB,
    )


def _targets(neo4j_session, rel, label, key):
    rows = neo4j_session.run(
        f"MATCH (:LoadBalancer)-[:{rel}]->(n:{label}) RETURN collect(n.{key}) AS ids",
    ).single()
    return set(rows['ids'])


def test_classic_load_balancer_links_stay_in_the_workspace(neo4j_session):
    _seed(neo4j_session)
    accounts = (OWN, SIBLING, OTHER)
    lb = {
        'DNSName': 'own-clb.us-east-1.elb.amazonaws.com', 'LoadBalancerName': 'web', 'CreatedTime': 'd',
        'region': REGION, 'VPCId': None, 'SourceSecurityGroup': None,
        # Groups and subnets shared in from the VPC owner (VPC sharing) belong to another account.
        'SecurityGroups': [f'sg-{a}' for a in accounts],
        'Subnets': [f'subnet-{a}' for a in accounts],
        'Instances': [{'InstanceId': f'i-{a}'} for a in accounts],
        'ListenerDescriptions': [],
    }

    load_balancers.load_load_balancers(neo4j_session, [lb], OWN, TAG, WORKSPACE)
    # rows naming another customer's load balancer
    load_balancers.load_load_balancer_listeners(
        neo4j_session,
        [{
            'load_balancer_id': OTHER_LB, 'consolelink': '',
            'listeners': [{'Listener': {'LoadBalancerPort': 443, 'Protocol': 'HTTPS'}}],
        }],
        OWN, TAG,
    )
    load_balancers.load_load_balancer_subnets(
        neo4j_session, [{'load_balancer_id': OTHER_LB, 'subnet_id': f'subnet-{OTHER}'}], OWN, WORKSPACE, TAG,
    )

    assert _targets(neo4j_session, 'MEMBER_OF_EC2_SECURITY_GROUP', 'EC2SecurityGroup', 'groupid') == {
        f'sg-{OWN}', f'sg-{SIBLING}',
    }
    assert _targets(neo4j_session, 'SUBNET', 'EC2Subnet', 'subnetid') == {f'subnet-{OWN}', f'subnet-{SIBLING}'}
    assert _targets(neo4j_session, 'EXPOSE', 'EC2Instance', 'instanceid') == {f'i-{OWN}'}
    claims = neo4j_session.run(
        "MATCH (a:AWSAccount)-[:RESOURCE]->(:EC2Instance{instanceid: $id}) RETURN collect(a.id) AS a", id=f'i-{OTHER}',
    ).single()
    assert claims['a'] == [OTHER]
    other_lb = neo4j_session.run(
        "MATCH (lb:LoadBalancer{id: $id}) RETURN size([(lb)-->(n) WHERE NOT n:AWSAccount | n]) AS out",
        id=OTHER_LB,
    ).single()
    assert other_lb['out'] == 0
