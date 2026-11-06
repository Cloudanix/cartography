import cartography.intel.aws.elasticbeanstalk
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777795'
OTHER_ACCOUNT_ID = '888888888895'


def _environment(account_id, name, **overrides):
    # Shape of transform_environments() output.
    return {
        'arn': f'arn:aws:elasticbeanstalk:us-east-1:{account_id}:environment/shop/{name}', 'name': name,
        'environmentId': f'e-{name}', 'applicationName': 'shop', 'status': 'Ready', 'health': 'Green',
        'healthStatus': 'Ok', 'tierName': 'WebServer', 'tierType': 'Standard', 'cname': f'{name}.eb.com',
        'endpointUrl': None, 'platformArn': None, 'solutionStackName': None, 'versionLabel': None,
        'region': 'us-east-1', 'consolelink': None, 'listenerProtocols': ['HTTP'], 'environmentType': 'LoadBalanced',
        'resourcesResolved': True, 'loadBalancerNames': [], 'instanceIds': [], **overrides,
    }


def _alb_arn(account_id, name):
    return f'arn:aws:elasticloadbalancing:us-east-1:{account_id}:loadbalancer/app/{name}/abc'


def load_network(neo4j_session, account_id, albs=(), elbs=(), instances=()):
    """Load balancers and instances as load_balancer_v2s.py / load_balancers.py / instances.py store them."""
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        FOREACH (name IN $albs |
            MERGE (a)-[:RESOURCE]->(lb:LoadBalancerV2{id: name + '.elb.amazonaws.com'})
            SET lb.name = name, lb.arn = $arn_prefix + name + '/abc', lb.region = 'us-east-1')
        FOREACH (name IN $elbs |
            MERGE (a)-[:RESOURCE]->(lb:LoadBalancer{id: name + '.elb.amazonaws.com'})
            SET lb.name = name, lb.region = 'us-east-1')
        FOREACH (iid IN $instances |
            MERGE (a)-[:RESOURCE]->(i:EC2Instance{id: iid}) SET i.instanceid = iid, i.region = 'us-east-1')
        """,
        account_id=account_id, albs=list(albs), elbs=list(elbs), instances=list(instances),
        arn_prefix=f'arn:aws:elasticloadbalancing:us-east-1:{account_id}:loadbalancer/app/',
    )


def test_load_environments_and_cleanup_only_this_account(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-eb', 'o-eb', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-eb-other', 'o-eb-other', OTHER_ACCOUNT_ID)
    load = cartography.intel.aws.elasticbeanstalk.load_environments
    load(neo4j_session, [_environment(OTHER_ACCOUNT_ID, 'eb-other')], OTHER_ACCOUNT_ID, TEST_UPDATE_TAG - 1)
    load(neo4j_session, [_environment(ACCOUNT_ID, 'eb-gone')], ACCOUNT_ID, TEST_UPDATE_TAG - 1)
    load(neo4j_session, [_environment(ACCOUNT_ID, 'eb-prod', listenerProtocols=['HTTPS'])], ACCOUNT_ID, TEST_UPDATE_TAG)

    cartography.intel.aws.elasticbeanstalk.cleanup_environments(
        neo4j_session, exposure_job_parameters('ws-eb', 'o-eb', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (a:AWSAccount)-[:RESOURCE]->(n:ElasticBeanstalkEnvironment) RETURN a.id AS account, n.name AS name, "
        "n.environment_id AS env_id, n.application_name AS app, n.listener_protocols AS protocols, "
        "n.tier_name AS tier",
    )
    environments = {r['name']: r for r in rows}
    assert set(environments) == {'eb-prod', 'eb-other'}
    prod = environments['eb-prod']
    assert (prod['account'], prod['env_id'], prod['app'], prod['protocols'], prod['tier']) == (
        ACCOUNT_ID, 'e-eb-prod', 'shop', ['HTTPS'], 'WebServer',
    )


def test_link_environment_resources_matches_only_this_account(neo4j_session):
    account, other = ACCOUNT_ID + '1', OTHER_ACCOUNT_ID + '1'
    create_test_org_account(neo4j_session, 'ws-ebl', 'o-ebl', account)
    create_test_org_account(neo4j_session, 'ws-ebl-other', 'o-ebl-other', other)
    load_network(neo4j_session, account, albs=['ebl-alb', 'ebl-alb-byname'], elbs=['ebl-elb'], instances=['i-ebl1'])
    # Another tenant has a classic ELB with the same name and an instance id: neither must be linked.
    load_network(neo4j_session, other, elbs=['ebl-elb-other'], instances=['i-ebl-other'])
    load = cartography.intel.aws.elasticbeanstalk.load_environments
    load(
        neo4j_session, [
            _environment(account, 'ebl-alb-env', loadBalancerNames=[_alb_arn(account, 'ebl-alb')]),
            _environment(account, 'ebl-name-env', loadBalancerNames=['ebl-alb-byname']),
            _environment(account, 'ebl-elb-env', loadBalancerNames=['ebl-elb', 'ebl-elb-other']),
            _environment(
                account, 'ebl-single', environmentType='SingleInstance', instanceIds=['i-ebl1', 'i-ebl-other'],
            ),
        ], account, TEST_UPDATE_TAG,
    )
    neo4j_session.run(
        "MATCH (env:ElasticBeanstalkEnvironment{name: 'ebl-single'}), (lb:LoadBalancerV2{name: 'ebl-alb'}) "
        "MERGE (env)-[:USES_LOAD_BALANCER{lastupdated: $tag}]->(lb)",
        tag=TEST_UPDATE_TAG - 1,
    )

    cartography.intel.aws.elasticbeanstalk.link_environment_resources(
        neo4j_session, exposure_job_parameters('ws-ebl', 'o-ebl', account, TEST_UPDATE_TAG),
    )

    rows = neo4j_session.run(
        "MATCH (env:ElasticBeanstalkEnvironment)-[r]->(t) WHERE env.name STARTS WITH 'ebl-' "
        "RETURN env.name AS env, type(r) AS rel, coalesce(t.name, t.id) AS target",
    )
    assert {(r['env'], r['rel'], r['target']) for r in rows} == {
        ('ebl-alb-env', 'USES_LOAD_BALANCER', 'ebl-alb'),
        ('ebl-name-env', 'USES_LOAD_BALANCER', 'ebl-alb-byname'),
        ('ebl-elb-env', 'USES_LOAD_BALANCER', 'ebl-elb'),
        ('ebl-single', 'HAS_INSTANCE', 'i-ebl1'),
    }
