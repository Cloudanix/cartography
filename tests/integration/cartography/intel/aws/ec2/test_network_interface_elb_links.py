import cartography.intel.aws.ec2.load_balancer_v2s
import cartography.intel.aws.ec2.load_balancers
import cartography.intel.aws.ec2.network_interfaces
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
NEXT_UPDATE_TAG = 123456790
REGION = 'us-east-1'
ACCOUNT_ID = '777777777793'
OTHER_ACCOUNT_ID = '888888888893'


def _classic_elb(account_id, name, region):
    return {
        # DNS names are globally unique (the node id); the name is not.
        'DNSName': f'{name}-{account_id}.{region}.elb.amazonaws.com',
        'LoadBalancerName': name,
        'CreatedTime': '2019-10-27 00:35:00',
        'Scheme': 'internet-facing',
        'region': region,
        'VPCId': None,
        'Subnets': [],
        'SecurityGroups': [],
        'SourceSecurityGroup': None,
        'Instances': [],
        'ListenerDescriptions': [],
    }


def _elbv2(account_id, kind, name, lb_id):
    return {
        'LoadBalancerArn': f'arn:aws:elasticloadbalancing:{REGION}:{account_id}:loadbalancer/{kind}/{name}/{lb_id}',
        # An ALB DNS name does not embed the ARN's id, so the ENI description cannot be turned into it.
        'DNSName': f'{name}-{account_id}.{REGION}.elb.amazonaws.com',
        'LoadBalancerName': name,
        'CreatedTime': '2024-01-01',
        'Type': 'application',
        'Scheme': 'internet-facing',
        'region': REGION,
        'AvailabilityZones': [],
    }


def _eni(eni_id, description, subnet_id):
    return {
        'NetworkInterfaceId': eni_id,
        'Description': description,
        'InterfaceType': 'interface',
        'MacAddress': f'mac-{eni_id}',
        'SubnetId': subnet_id,
        'Groups': [],
        'PrivateIpAddresses': [],
    }


def _sync_enis(neo4j_session, enis, update_tag):
    data = cartography.intel.aws.ec2.network_interfaces.transform_network_interface_data(enis, REGION, ACCOUNT_ID)
    cartography.intel.aws.ec2.network_interfaces.load_network_data(
        neo4j_session, REGION, ACCOUNT_ID, update_tag,
        data.network_interface_list, data.private_ip_list, data.subnet_list, data.sg_list,
    )


def _links(neo4j_session, rel_label):
    rows = neo4j_session.run(
        f"""
        MATCH (lb)-[:{rel_label}]->(n)
        WHERE (lb:LoadBalancer OR lb:LoadBalancerV2) AND lb.name STARTS WITH 'enilb-'
        RETURN lb.arn AS lb, n.id AS target
        """,
    )
    return {(row['lb'], row['target']) for row in rows}


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-enilb', 'o-enilb', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-enilb-other', 'o-enilb-other', OTHER_ACCOUNT_ID)
    # Classic names repeat across regions and tenants; the other tenant also has an ALB with the same name.
    elb = cartography.intel.aws.ec2.load_balancers
    elb.load_load_balancers(
        neo4j_session,
        [_classic_elb(ACCOUNT_ID, 'enilb-classic', REGION), _classic_elb(ACCOUNT_ID, 'enilb-classic', 'us-west-2')],
        ACCOUNT_ID, TEST_UPDATE_TAG, 'ws-enilb',
    )
    elb.load_load_balancers(
        neo4j_session, [_classic_elb(OTHER_ACCOUNT_ID, 'enilb-classic', REGION)], OTHER_ACCOUNT_ID, TEST_UPDATE_TAG,
        'ws-enilb-other',
    )
    elbv2 = cartography.intel.aws.ec2.load_balancer_v2s
    elbv2.load_load_balancer_v2s(
        neo4j_session, [_elbv2(ACCOUNT_ID, 'app', 'enilb-alb', '50dc6c495c0c9188')],
        ACCOUNT_ID, TEST_UPDATE_TAG, REGION, 'ws-enilb',
    )
    elbv2.load_load_balancer_v2s(
        neo4j_session, [_elbv2(OTHER_ACCOUNT_ID, 'app', 'enilb-alb', '50dc6c495c0c9188')],
        OTHER_ACCOUNT_ID, TEST_UPDATE_TAG, REGION, 'ws-enilb-other',
    )


def _classic_arn(account_id):
    # load_load_balancers builds the real classic ARN from the load balancer's name.
    return f'arn:aws:elasticloadbalancing:{REGION}:{account_id}:loadbalancer/enilb-classic'


ALB_ARN = f'arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT_ID}:loadbalancer/app/enilb-alb/50dc6c495c0c9188'


def test_eni_links_to_its_own_accounts_load_balancer(neo4j_session):
    _seed(neo4j_session)

    _sync_enis(
        neo4j_session,
        [
            _eni('eni-enilb-classic', 'ELB enilb-classic', 'subnet-enilb-a'),
            _eni('eni-enilb-alb', 'ELB app/enilb-alb/50dc6c495c0c9188', 'subnet-enilb-b'),
            # An NLB that was not synced: no edge, and no node created for it.
            _eni('eni-enilb-nlb', 'ELB net/enilb-nlb/0123456789abcdef', 'subnet-enilb-b'),
            _eni('eni-enilb-plain', '', 'subnet-enilb-c'),
        ],
        TEST_UPDATE_TAG,
    )

    # Own account, own region only: never the us-west-2 namesake, never the other tenant's namesakes.
    assert _links(neo4j_session, 'NETWORK_INTERFACE') == {
        (_classic_arn(ACCOUNT_ID), 'eni-enilb-classic'),
        (ALB_ARN, 'eni-enilb-alb'),
    }
    assert _links(neo4j_session, 'PART_OF_SUBNET') == {
        (_classic_arn(ACCOUNT_ID), 'subnet-enilb-a'),
        (ALB_ARN, 'subnet-enilb-b'),
    }


def test_eni_load_balancer_links_are_cleaned_up_when_stale(neo4j_session):
    _seed(neo4j_session)
    _sync_enis(
        neo4j_session,
        [
            _eni('eni-enilb-classic', 'ELB enilb-classic', 'subnet-enilb-a'),
            _eni('eni-enilb-alb', 'ELB app/enilb-alb/50dc6c495c0c9188', 'subnet-enilb-b'),
        ],
        TEST_UPDATE_TAG,
    )

    # Next sync: both load balancers left those subnets (their ENIs are gone).
    _sync_enis(neo4j_session, [_eni('eni-enilb-plain', '', 'subnet-enilb-c')], NEXT_UPDATE_TAG)
    cartography.intel.aws.ec2.network_interfaces.cleanup_network_interfaces(
        neo4j_session, exposure_job_parameters('ws-enilb', 'o-enilb', ACCOUNT_ID, NEXT_UPDATE_TAG),
    )

    assert _links(neo4j_session, 'NETWORK_INTERFACE') == set()
    assert _links(neo4j_session, 'PART_OF_SUBNET') == set()
