import json

import cartography.intel.aws.ec2.load_balancer_v2s
import cartography.intel.aws.ec2.security_groups
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import create_test_security_group_rule
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
WORKSPACE_ID = 'ws-lsn'
ORG_ID = 'o-lsn'
ACCOUNT_ID = '777777777797'
TLS_POLICY = 'ELBSecurityPolicy-2016-08'


def _listener(lb_name, port, protocol, ssl_policy=None):
    listener = {
        'ListenerArn': f'arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT_ID}:listener/net/{lb_name}/x/{port}',
        'Port': port,
        'Protocol': protocol,
    }
    if ssl_policy:
        listener['SslPolicy'] = ssl_policy
    return listener


def _lb(name, scheme, listeners, security_groups=None, subnet=None, lb_type='network'):
    return {
        'DNSName': f'{name}.elb.us-east-1.amazonaws.com',
        'CreatedTime': '10-27-2019 12:35AM',
        'LoadBalancerName': name,
        'LoadBalancerArn': f'arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT_ID}:loadbalancer/net/{name}/x',
        'Type': lb_type,
        'region': 'us-east-1',
        'Scheme': scheme,
        'AvailabilityZones': [{'SubnetId': subnet}] if subnet else [],
        'SecurityGroups': security_groups or [],
        'Listeners': listeners,
    }


def _security_group(neo4j_session, group_id, cidr, port):
    create_test_security_group_rule(neo4j_session, group_id, cidr, 'tcp', port, port)
    # The ELBv2 loader links a load balancer to its groups by groupid.
    neo4j_session.run("MATCH (sg:EC2SecurityGroup{id: $id}) SET sg.groupid = $id", id=group_id)


def _setup(neo4j_session):
    create_test_org_account(neo4j_session, WORKSPACE_ID, ORG_ID, ACCOUNT_ID)
    # 443 open to the world, 9122 open to one /32 only: the shape of a customer NLB that
    # reported 9122 as internet-exposed.
    _security_group(neo4j_session, 'sg-lsn-tls-open', '0.0.0.0/0', 443)
    _security_group(neo4j_session, 'sg-lsn-admin-ip', '100.28.157.253/32', 9122)
    cartography.intel.aws.ec2.load_balancer_v2s.load_load_balancer_v2s(
        neo4j_session,
        [
            _lb(
                'lsn-nlb-sg', 'internet-facing',
                [_listener('lsn-nlb-sg', 443, 'TLS', TLS_POLICY), _listener('lsn-nlb-sg', 9122, 'TCP')],
                security_groups=['sg-lsn-tls-open', 'sg-lsn-admin-ip'],
            ),
            # NLB without security groups: every listener is reachable from the internet.
            _lb('lsn-nlb-nosg', 'internet-facing', [_listener('lsn-nlb-nosg', 8080, 'TCP')]),
            _lb('lsn-nlb-internal', 'internal', [_listener('lsn-nlb-internal', 8080, 'TCP')]),
        ],
        ACCOUNT_ID, TEST_UPDATE_TAG, 'us-east-1',
    )
    run_analysis_job(
        'aws_ec2_elb_asset_exposure.json', neo4j_session,
        exposure_job_parameters(WORKSPACE_ID, ORG_ID, ACCOUNT_ID, TEST_UPDATE_TAG),
    )


def _listeners(neo4j_session):
    rows = neo4j_session.run(
        "MATCH (lb:LoadBalancerV2)-[:ELBV2_LISTENER]->(l:ELBV2Listener) "
        "WHERE lb.name STARTS WITH 'lsn-' OR lb.name STARTS WITH 'lbl-' "
        "RETURN lb.name AS lb, l.port AS port, l.exposed_internet AS exposed, l.exposed_internet_type AS types, "
        "l.publicContext AS context",
    )
    return {(r['lb'], r['port']): r for r in rows}


def _lb_context(neo4j_session, name):
    context = neo4j_session.run(
        "MATCH (lb:LoadBalancerV2{name: $name}) RETURN lb.publicContext AS context", name=name,
    ).single()['context']
    return json.loads(context)[0]['context'][0]


def test_elbv2_public_context_carries_the_listener_ssl_policy(neo4j_session):
    _setup(neo4j_session)

    lb_listeners = {item['port']: item for item in _lb_context(neo4j_session, 'lsn-nlb-sg')['listeners']}
    assert lb_listeners['443']['sslPolicy'] == TLS_POLICY
    assert lb_listeners['9122']['sslPolicy'] is None

    listener_context = json.loads(_listeners(neo4j_session)[('lsn-nlb-sg', 443)]['context'])[0]['context'][0]
    assert listener_context['sslPolicy'] == TLS_POLICY


def test_elbv2_listener_behind_a_security_group_is_exposed_only_by_a_matching_open_rule(neo4j_session):
    _setup(neo4j_session)
    listeners = _listeners(neo4j_session)

    tls = listeners[('lsn-nlb-sg', 443)]
    assert tls['exposed'] is True
    assert tls['types'] == ['loadbalancer_unrestricted_inbound_traffic_ipv4']

    # Allowed from a single /32 only: the load balancer's scheme alone does not make it exposed.
    admin = listeners[('lsn-nlb-sg', 9122)]
    assert admin['exposed'] is None
    assert admin['context'] is None

    # The load balancer itself stays exposed through its open 443 listener.
    lb = _lb_context(neo4j_session, 'lsn-nlb-sg')
    assert 'unrestricted_inbound_traffic_ipv4' in lb['exposureTypes']


def test_elbv2_listener_without_security_groups_is_exposed_by_scheme(neo4j_session):
    _setup(neo4j_session)
    listeners = _listeners(neo4j_session)

    assert listeners[('lsn-nlb-nosg', 8080)]['exposed'] is True
    assert listeners[('lsn-nlb-nosg', 8080)]['types'] == ['loadbalancer_scheme']
    assert listeners[('lsn-nlb-internal', 8080)]['exposed'] is None


PUBLIC_SUBNET = 'subnet-lbl-public'


def _public_subnet(neo4j_session):
    # A subnet whose route table sends 0.0.0.0/0 to an internet gateway.
    neo4j_session.run(
        """
        MERGE (s:EC2Subnet{subnetid: $subnet})
        MERGE (s)-[:HAS_EXPLICIT_ASSOCIATION]->(:EC2RouteTableAssociation{id: $subnet + '-assoc'})
            <-[:HAS_ASSOCIATION]-(rtb:EC2RouteTable{id: $subnet + '-rtb'})
        MERGE (rtb)-[:MEMBER_OF_ROUTE_TABLE]->(:EC2Route{id: $subnet + '-route', destination_cidr_block: '0.0.0.0/0',
            gateway_id: 'igw-lbl'})
        """,
        subnet=PUBLIC_SUBNET,
    )


def _prefix_list_group(neo4j_session, group_id, port):
    # Loaded through the real rule loader so the test reads what a sync writes.
    neo4j_session.run("MERGE (sg:EC2SecurityGroup{id: $id}) SET sg.groupid = $id, sg.name = $id", id=group_id)
    cartography.intel.aws.ec2.security_groups.load_ec2_security_group_rules(
        neo4j_session,
        [{
            'GroupId': group_id,
            'IpPermissions': [{
                'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port, 'IpRanges': [], 'Ipv6Ranges': [],
                'PrefixListIds': [{'PrefixListId': 'pl-3b927c52'}],
            }],
            'IpPermissionsEgress': [],
        }],
        TEST_UPDATE_TAG,
    )


def _setup_lb_level(neo4j_session):
    _setup(neo4j_session)
    _public_subnet(neo4j_session)
    _security_group(neo4j_session, 'sg-lbl-corp-only', '10.0.0.0/8', 443)
    _prefix_list_group(neo4j_session, 'sg-lbl-cloudfront', 443)
    https = 'HTTPS'
    cartography.intel.aws.ec2.load_balancer_v2s.load_load_balancer_v2s(
        neo4j_session,
        [
            _lb(
                'lbl-alb-private-sg', 'internet-facing', [_listener('lbl-alb-private-sg', 443, https, TLS_POLICY)],
                security_groups=['sg-lbl-corp-only'], subnet=PUBLIC_SUBNET, lb_type='application',
            ),
            _lb(
                'lbl-alb-prefix-list', 'internet-facing', [_listener('lbl-alb-prefix-list', 443, https, TLS_POLICY)],
                security_groups=['sg-lbl-cloudfront'], subnet=PUBLIC_SUBNET, lb_type='application',
            ),
            _lb(
                'lbl-nlb-nosg', 'internet-facing', [_listener('lbl-nlb-nosg', 443, 'TCP')], subnet=PUBLIC_SUBNET,
            ),
        ],
        ACCOUNT_ID, TEST_UPDATE_TAG, 'us-east-1',
    )
    run_analysis_job(
        'aws_ec2_elb_asset_exposure.json', neo4j_session,
        exposure_job_parameters(WORKSPACE_ID, ORG_ID, ACCOUNT_ID, TEST_UPDATE_TAG),
    )


def _lb_exposure(neo4j_session, name):
    row = neo4j_session.run(
        "MATCH (lb:LoadBalancerV2{name: $name}) RETURN lb.exposed_internet AS exposed, "
        "lb.exposed_internet_type AS types, lb.publicContext AS context",
        name=name,
    ).single()
    return row['exposed'], sorted(row['types'] or []), row['context']


def test_elbv2_with_security_groups_is_exposed_only_through_an_open_source(neo4j_session):
    _setup_lb_level(neo4j_session)

    # Internet-facing, in a public subnet, but its group admits 10.0.0.0/8 only.
    assert _lb_exposure(neo4j_session, 'lbl-alb-private-sg') == (None, [], None)
    assert _listeners(neo4j_session)[('lbl-alb-private-sg', 443)]['exposed'] is None

    # A prefix-list source (e.g. CloudFront origin-facing) cannot be resolved to CIDRs: stays exposed.
    exposed, types, _ = _lb_exposure(neo4j_session, 'lbl-alb-prefix-list')
    assert (exposed, types) == (True, ['prefix_list_inbound', 'public_subnet_ipv4'])
    assert _listeners(neo4j_session)[('lbl-alb-prefix-list', 443)]['types'] == ['loadbalancer_prefix_list_inbound']

    # The open-443 NLB keeps its open-rule exposure.
    exposed, types, _ = _lb_exposure(neo4j_session, 'lsn-nlb-sg')
    assert (exposed, types) == (True, ['unrestricted_inbound_traffic_ipv4'])


def test_elbv2_without_security_groups_is_exposed_by_scheme_and_subnet(neo4j_session):
    _setup_lb_level(neo4j_session)

    exposed, types, _ = _lb_exposure(neo4j_session, 'lbl-nlb-nosg')
    assert (exposed, types) == (True, ['public_subnet_ipv4', 'scheme'])
    assert _lb_exposure(neo4j_session, 'lsn-nlb-internal')[0] is None
