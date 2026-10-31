import json

import cartography.intel.aws.elasticbeanstalk
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters
from tests.integration.cartography.intel.aws.test_elasticbeanstalk import _alb_arn
from tests.integration.cartography.intel.aws.test_elasticbeanstalk import _environment
from tests.integration.cartography.intel.aws.test_elasticbeanstalk import load_network

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777796'
OTHER_ACCOUNT_ID = '888888888896'


def _expose(neo4j_session, label, key, value, types):
    # What aws_ec2_elb_asset_exposure.json / aws_ec2_instance_asset_exposure.json leave on an exposed node.
    neo4j_session.run(
        f"MATCH (n:{label}{{{key}: $value}}) SET n.exposed_internet = true, n.exposed_internet_type = $types, "
        "n.scheme = 'internet-facing', n.dnsname = n.id, n.publicipaddress = '54.9.9.9'",
        value=value, types=types,
    )


def _setup(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-ebx', 'o-ebx', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-ebx-other', 'o-ebx-other', OTHER_ACCOUNT_ID)
    load_network(
        neo4j_session, ACCOUNT_ID, albs=['ebx-alb-public', 'ebx-alb-internal'], elbs=['ebx-elb-public'],
        instances=['i-ebx-public', 'i-ebx-private', 'i-ebx-worker'],
    )
    load_network(neo4j_session, OTHER_ACCOUNT_ID, albs=['ebx-alb-other'])
    _expose(neo4j_session, 'LoadBalancerV2', 'name', 'ebx-alb-public', ['scheme'])
    _expose(neo4j_session, 'LoadBalancerV2', 'name', 'ebx-alb-other', ['scheme'])
    _expose(neo4j_session, 'LoadBalancer', 'name', 'ebx-elb-public', ['scheme', 'public_subnet_ipv4'])
    _expose(neo4j_session, 'EC2Instance', 'id', 'i-ebx-public', ['public_subnet_ipv4'])
    _expose(neo4j_session, 'EC2Instance', 'id', 'i-ebx-worker', ['public_subnet_ipv4'])
    single = {'environmentType': 'SingleInstance'}
    cartography.intel.aws.elasticbeanstalk.load_environments(
        neo4j_session, [
            _environment(ACCOUNT_ID, 'ebx-alb-public', loadBalancerNames=[_alb_arn(ACCOUNT_ID, 'ebx-alb-public')]),
            _environment(ACCOUNT_ID, 'ebx-alb-internal', loadBalancerNames=[_alb_arn(ACCOUNT_ID, 'ebx-alb-internal')]),
            _environment(ACCOUNT_ID, 'ebx-elb-public', loadBalancerNames=['ebx-elb-public']),
            _environment(ACCOUNT_ID, 'ebx-single-public', instanceIds=['i-ebx-public'], **single),
            _environment(ACCOUNT_ID, 'ebx-single-private', instanceIds=['i-ebx-private'], **single),
            _environment(
                ACCOUNT_ID, 'ebx-worker', tierName='Worker', tierType='SQS/HTTP', instanceIds=['i-ebx-worker'],
                resourcesResolved=False,
            ),
            _environment(ACCOUNT_ID, 'ebx-call-failed', resourcesResolved=False),
            _environment(ACCOUNT_ID, 'ebx-lb-missing', loadBalancerNames=['ebx-elb-gone']),
            _environment(ACCOUNT_ID, 'ebx-instance-missing', instanceIds=['i-ebx-gone'], **single),
            _environment(ACCOUNT_ID, 'ebx-empty'),
            _environment(ACCOUNT_ID, 'ebx-closed-since', loadBalancerNames=[_alb_arn(ACCOUNT_ID, 'ebx-alb-internal')]),
        ], ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.elasticbeanstalk.load_environments(
        neo4j_session,
        [_environment(OTHER_ACCOUNT_ID, 'ebx-other', loadBalancerNames=[_alb_arn(OTHER_ACCOUNT_ID, 'ebx-alb-other')])],
        OTHER_ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    neo4j_session.run(
        "MATCH (n:ElasticBeanstalkEnvironment{name: 'ebx-closed-since'}) "
        "SET n.exposed_internet = true, n.exposed_internet_type = ['load_balancer'], n.publicContext = '[]'",
    )
    params = exposure_job_parameters('ws-ebx', 'o-ebx', ACCOUNT_ID, TEST_UPDATE_TAG)
    cartography.intel.aws.elasticbeanstalk.link_environment_resources(neo4j_session, params)
    cartography.intel.aws.elasticbeanstalk.link_environment_resources(
        neo4j_session, exposure_job_parameters('ws-ebx-other', 'o-ebx-other', OTHER_ACCOUNT_ID, TEST_UPDATE_TAG),
    )
    return params


def test_beanstalk_environment_public_through_its_front_door(neo4j_session):
    params = _setup(neo4j_session)

    run_analysis_job('aws_elasticbeanstalk_asset_exposure.json', neo4j_session, params)

    rows = neo4j_session.run(
        "MATCH (n:ElasticBeanstalkEnvironment) WHERE n.name STARTS WITH 'ebx-' RETURN n.name AS name, "
        "n.exposed_internet AS exposed, n.exposed_internet_type AS types, n.publicContext AS context",
    )
    environments = {r['name']: r for r in rows}
    assert {n: r['types'] for n, r in environments.items() if r['exposed']} == {
        'ebx-alb-public': ['load_balancer'],
        'ebx-elb-public': ['load_balancer'],
        'ebx-single-public': ['instance'],
        'ebx-call-failed': ['unresolved'],
        'ebx-lb-missing': ['unresolved'],
        'ebx-instance-missing': ['unresolved'],
    }
    assert environments['ebx-closed-since']['context'] is None
    # Other tenant: never evaluated by this account's run.
    assert environments['ebx-other']['exposed'] is None

    context = json.loads(environments['ebx-alb-public']['context'])[0]
    assert (context['resource'], context['resourceType']) == (
        f'arn:aws:elasticbeanstalk:us-east-1:{ACCOUNT_ID}:environment/shop/ebx-alb-public',
        'aws-compute-elasticbeanstalk-environment',
    )
    detail = context['context'][0]
    assert (detail['environmentId'], detail['cname'], detail['tier']) == (
        'e-ebx-alb-public', 'ebx-alb-public.eb.com', 'WebServer',
    )
    assert detail['loadBalancers'] == [{
        'name': 'ebx-alb-public', 'dnsName': 'ebx-alb-public.elb.amazonaws.com', 'scheme': 'internet-facing',
        'exposureTypes': ['scheme'],
    }]
    instance = json.loads(environments['ebx-single-public']['context'])[0]['context'][0]
    assert instance['instances'] == [
        {'instanceId': 'i-ebx-public', 'publicIp': '54.9.9.9', 'exposureTypes': ['public_subnet_ipv4']},
    ]
    missing = json.loads(environments['ebx-lb-missing']['context'])[0]['context'][0]
    assert (missing['resourcesResolved'], missing['unresolvedLoadBalancers'], missing['unresolvedInstances']) == (
        True, ['ebx-elb-gone'], [],
    )
