import json

import cartography.intel.aws.ec2.load_balancer_v2s
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


def _lb(name, scheme, listeners, security_groups=None):
    return {
        'DNSName': f'{name}.elb.us-east-1.amazonaws.com',
        'CreatedTime': '10-27-2019 12:35AM',
        'LoadBalancerName': name,
        'LoadBalancerArn': f'arn:aws:elasticloadbalancing:us-east-1:{ACCOUNT_ID}:loadbalancer/net/{name}/x',
        'Type': 'network',
        'region': 'us-east-1',
        'Scheme': scheme,
        'AvailabilityZones': [],
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
        "MATCH (lb:LoadBalancerV2)-[:ELBV2_LISTENER]->(l:ELBV2Listener) WHERE lb.name STARTS WITH 'lsn-' "
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
