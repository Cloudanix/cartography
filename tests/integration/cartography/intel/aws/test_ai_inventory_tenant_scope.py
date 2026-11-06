from cartography.intel.aws import bedrock
from cartography.intel.aws import sagemaker
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 123456789
ACCOUNT_ID = '777777777811'
OTHER_ACCOUNT_ID = '888888888811'
REGION = 'us-east-1'
OTHER_REGION = 'us-west-2'
DOMAIN_ID = 'd-shared00001'


def _sm_arn(account_id, kind, name, region=REGION):
    return f'arn:aws:sagemaker:{region}:{account_id}:{kind}/{name}'


def _load_named_sagemaker_resources(neo4j_session, account_id, region):
    # Console-style names that every tenant has, so a lookup by name alone reaches the other tenant.
    sagemaker.load_models(
        neo4j_session,
        [{'ModelName': 'model-1', 'ModelArn': _sm_arn(account_id, 'model', 'model-1', region), 'region': region}],
        account_id, TAG,
    )
    sagemaker.load_endpoint_configs(
        neo4j_session,
        [{
            'EndpointConfigName': 'config-1',
            'EndpointConfigArn': _sm_arn(account_id, 'endpoint-config', 'config-1', region),
            'ModelNames': ['model-1'], 'region': region,
        }],
        account_id, TAG,
    )
    sagemaker.load_endpoints(
        neo4j_session,
        [{
            'EndpointName': 'endpoint-1', 'EndpointArn': _sm_arn(account_id, 'endpoint', 'endpoint-1', region),
            'EndpointConfigName': 'config-1', 'region': region,
        }],
        account_id, TAG,
    )
    sagemaker.load_model_package_groups(
        neo4j_session,
        [{
            'ModelPackageGroupName': 'group-1',
            'ModelPackageGroupArn': _sm_arn(account_id, 'model-package-group', 'group-1', region), 'region': region,
        }],
        account_id, TAG,
    )
    sagemaker.load_domains(
        neo4j_session,
        [{'DomainId': DOMAIN_ID, 'DomainArn': _sm_arn(account_id, 'domain', DOMAIN_ID, region), 'region': region}],
        account_id, TAG,
    )


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-ai', 'o-ai', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-ai-other', 'o-ai-other', OTHER_ACCOUNT_ID)
    _load_named_sagemaker_resources(neo4j_session, OTHER_ACCOUNT_ID, REGION)
    _load_named_sagemaker_resources(neo4j_session, ACCOUNT_ID, OTHER_REGION)
    _load_named_sagemaker_resources(neo4j_session, ACCOUNT_ID, REGION)


def _linked(neo4j_session, label, key, value, rel):
    rows = neo4j_session.run(
        f"MATCH (n:{label}{{{key}: $value}})-[:{rel}]-(m) RETURN coalesce(m.arn, m.id) AS id", value=value,
    )
    return {row['id'] for row in rows}


def test_sagemaker_name_links_stay_in_the_account_and_region(neo4j_session):
    _seed(neo4j_session)
    sagemaker.load_monitoring_schedules(
        neo4j_session,
        [{
            'MonitoringScheduleName': 'schedule-1',
            'MonitoringScheduleArn': _sm_arn(ACCOUNT_ID, 'monitoring-schedule', 's'),
            'EndpointName': 'endpoint-1', 'region': REGION,
        }],
        ACCOUNT_ID, TAG,
    )
    sagemaker.load_model_packages(
        neo4j_session,
        [{
            'ModelPackageName': 'group-1', 'ModelPackageArn': _sm_arn(ACCOUNT_ID, 'model-package', 'group-1/1'),
            'ModelPackageGroupName': 'group-1', 'region': REGION,
        }],
        ACCOUNT_ID, TAG,
    )

    endpoint = _sm_arn(ACCOUNT_ID, 'endpoint', 'endpoint-1')
    config = _sm_arn(ACCOUNT_ID, 'endpoint-config', 'config-1')
    assert _linked(neo4j_session, 'AWSSagemakerEndpoint', 'arn', endpoint, 'USES_CONFIG') == {config}
    assert _linked(neo4j_session, 'AWSSagemakerEndpointConfig', 'arn', config, 'HOSTS') == {
        _sm_arn(ACCOUNT_ID, 'model', 'model-1'),
    }
    assert _linked(
        neo4j_session, 'AWSSagemakerMonitoringSchedule', 'arn', _sm_arn(ACCOUNT_ID, 'monitoring-schedule', 's'),
        'MONITORS',
    ) == {endpoint}
    assert _linked(
        neo4j_session, 'AWSSagemakerModelPackage', 'arn', _sm_arn(ACCOUNT_ID, 'model-package', 'group-1/1'),
        'MEMBER_OF',
    ) == {_sm_arn(ACCOUNT_ID, 'model-package-group', 'group-1')}


def test_sagemaker_studio_children_reach_only_the_accounts_domain(neo4j_session):
    _seed(neo4j_session)
    profile = {'DomainId': DOMAIN_ID, 'UserProfileName': 'default-user', 'region': REGION}
    profile['id'] = _sm_arn(ACCOUNT_ID, 'user-profile', f'{DOMAIN_ID}/default-user')
    space = {'DomainId': DOMAIN_ID, 'SpaceName': 'space-1', 'region': REGION}
    space['id'] = _sm_arn(ACCOUNT_ID, 'space', f'{DOMAIN_ID}/space-1')
    app = {'DomainId': DOMAIN_ID, 'UserProfileName': 'default-user', 'AppType': 'JupyterServer', 'AppName': 'default'}
    app.update(region=REGION, id=_sm_arn(ACCOUNT_ID, 'app', f'{DOMAIN_ID}/default-user/JupyterServer/default'))
    sagemaker.load_user_profiles(neo4j_session, [profile], ACCOUNT_ID, TAG)
    sagemaker.load_spaces(neo4j_session, [space], ACCOUNT_ID, TAG)
    sagemaker.load_apps(neo4j_session, [app], ACCOUNT_ID, TAG)

    # The other tenant has a domain with the same DomainId: never linked.
    own_domain = {_sm_arn(ACCOUNT_ID, 'domain', DOMAIN_ID)}
    for label, node, rel in (
        ('AWSSagemakerUserProfile', profile, 'HAS_USER_PROFILE'),
        ('AWSSagemakerSpace', space, 'HAS_SPACE'),
        ('AWSSagemakerApp', app, 'HAS_APP'),
    ):
        domains = _linked(neo4j_session, label, 'id', node['id'], rel)
        assert own_domain <= domains
        assert _sm_arn(OTHER_ACCOUNT_ID, 'domain', DOMAIN_ID) not in domains


def test_sagemaker_notebook_links_only_the_accounts_kms_key_and_network(neo4j_session):
    _seed(neo4j_session)
    own_key = f'arn:aws:kms:{REGION}:{ACCOUNT_ID}:key/own-key'
    other_key = f'arn:aws:kms:{REGION}:{OTHER_ACCOUNT_ID}:key/other-key'
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $account_id}), (other:AWSAccount{id: $other_account_id})
        MERGE (own)-[:RESOURCE]->(:KMSKey{id: 'own-key', arn: $own_key})
        MERGE (other)-[:RESOURCE]->(:KMSKey{id: 'other-key', arn: $other_key})
        MERGE (own)-[:RESOURCE]->(:EC2SecurityGroup{id: 'sg-own'})
        // A RAM-shared subnet: owned by the other account.
        MERGE (other)-[:RESOURCE]->(:EC2Subnet{subnetid: 'subnet-shared'})
        """,
        account_id=ACCOUNT_ID, other_account_id=OTHER_ACCOUNT_ID, own_key=own_key, other_key=other_key,
    )
    notebooks = [
        {
            'NotebookInstanceName': name, 'NotebookInstanceArn': _sm_arn(ACCOUNT_ID, 'notebook-instance', name),
            'KmsKeyId': key, 'SubnetId': 'subnet-shared', 'SecurityGroups': ['sg-own', 'sg-not-synced'],
            'region': REGION,
        }
        for name, key in (('by-arn', own_key), ('by-alias', 'alias/aws/sagemaker'), ('cross-account', other_key))
    ]

    sagemaker.load_notebook_instances(neo4j_session, notebooks, ACCOUNT_ID, TAG)

    def linked(name, rel):
        return _linked(
            neo4j_session, 'AWSSagemakerNotebookInstance', 'arn', _sm_arn(ACCOUNT_ID, 'notebook-instance', name), rel,
        )
    assert linked('by-arn', 'ENCRYPTED_BY') == {own_key}
    assert linked('by-alias', 'ENCRYPTED_BY') == set()
    assert linked('cross-account', 'ENCRYPTED_BY') == set()
    assert linked('by-arn', 'IN_SUBNET') == set()
    assert linked('by-arn', 'MEMBER_OF_EC2_SECURITY_GROUP') == {'sg-own'}
    # No stubs: no key for the alias or the foreign key ARN, no unsynced security group.
    assert neo4j_session.run(
        "MATCH (k:KMSKey) WHERE k.id IN ['alias/aws/sagemaker', $other_key] RETURN count(k) AS n", other_key=other_key,
    ).single()['n'] == 0
    assert neo4j_session.run(
        "MATCH (sg:EC2SecurityGroup{id: 'sg-not-synced'}) RETURN count(sg) AS n",
    ).single()['n'] == 0


def test_bedrock_links_reach_only_the_accounts_resources(neo4j_session):
    _seed(neo4j_session)
    agent_arn = f'arn:aws:bedrock:{REGION}:{ACCOUNT_ID}:agent/AGENT00001'
    own_fn = f'arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:agent-tools'
    other_fn = f'arn:aws:lambda:{REGION}:{OTHER_ACCOUNT_ID}:function:agent-tools'
    custom_model = f'arn:aws:bedrock:{REGION}:{ACCOUNT_ID}:custom-model/base/tuned'
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $account_id}), (other:AWSAccount{id: $other_account_id})
        MERGE (own)-[:RESOURCE]->(:AWSLambda{id: $own_fn})
        MERGE (other)-[:RESOURCE]->(:AWSLambda{id: $other_fn})
        """,
        account_id=ACCOUNT_ID, other_account_id=OTHER_ACCOUNT_ID, own_fn=own_fn, other_fn=other_fn,
    )
    bedrock.load_bedrock_agents(
        neo4j_session, [{'arn': agent_arn, 'agentId': 'AGENT00001', 'region': REGION}], ACCOUNT_ID, TAG,
    )
    bedrock.load_custom_models(
        neo4j_session, [{'modelArn': custom_model, 'modelName': 'tuned', 'region': REGION}], ACCOUNT_ID, TAG,
    )
    groups = [
        {
            'id': f'{agent_arn}/action-group/DRAFT/{name}', 'actionGroupId': name, 'agentArn': agent_arn,
            'lambdaFunctionArn': bedrock._unqualified_lambda_arn(fn), 'region': REGION,
        }
        for name, fn in (('own', own_fn + ':PROD'), ('other', other_fn), ('unsynced', own_fn + '-missing'))
    ]
    bedrock.load_bedrock_agent_action_groups(neo4j_session, groups, ACCOUNT_ID, TAG)
    bedrock.load_bedrock_provisioned_throughputs(
        neo4j_session,
        [
            {'provisionedModelArn': f'{custom_model}-pt', 'modelArn': custom_model, 'region': REGION},
            {
                'provisionedModelArn': f'{custom_model}-fm-pt', 'region': REGION,
                'modelArn': f'arn:aws:bedrock:{REGION}::foundation-model/anthropic.claude-v2',
            },
        ],
        ACCOUNT_ID, TAG,
    )

    def invokes(name):
        group_id = f'{agent_arn}/action-group/DRAFT/{name}'
        return _linked(neo4j_session, 'AWSBedrockAgentActionGroup', 'id', group_id, 'INVOKES')
    assert invokes('own') == {own_fn}
    assert invokes('other') == set()
    assert invokes('unsynced') == set()
    assert neo4j_session.run(
        "MATCH (l:AWSLambda) WHERE l.id = $missing RETURN count(l) AS n", missing=own_fn + '-missing',
    ).single()['n'] == 0
    assert _linked(
        neo4j_session, 'AWSBedrockProvisionedModelThroughput', 'arn', f'{custom_model}-pt', 'PROVISIONS_MODEL',
    ) == {custom_model}
    # The public foundation-model catalog is not synced, nor created as a link target.
    assert neo4j_session.run("MATCH (m:AWSBedrockFoundationModel) RETURN count(m) AS n").single()['n'] == 0
