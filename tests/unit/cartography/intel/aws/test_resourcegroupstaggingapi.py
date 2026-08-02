import copy

import cartography.intel.aws.resourcegroupstaggingapi as rgta
import tests.data.aws.resourcegroupstaggingapi as test_data


def test_compute_resource_id():
    """
    Test that the id_func function pointer behaves as expected and returns the instanceid from an EC2Instance's ARN.
    """
    tag_mapping = {
        'ResourceARN': 'arn:aws:ec2:us-east-1:1234:instance/i-abcd',
        'Tags': [{
            'Key': 'my_key',
            'Value': 'my_value',
        }],
    }
    ec2_short_id = 'i-abcd'
    assert ec2_short_id == rgta.compute_resource_id(tag_mapping, 'ec2:instance')


def test_get_bucket_name_from_arn():
    arn = 'arn:aws:s3:::bucket_name'
    assert 'bucket_name' == rgta.get_bucket_name_from_arn(arn)


def test_get_short_id_from_ec2_arn():
    arn = 'arn:aws:ec2:us-east-1:test_account:instance/i-1337'
    assert 'i-1337' == rgta.get_short_id_from_ec2_arn(arn)


def test_get_short_id_from_elb_arn():
    arn = 'arn:aws:elasticloadbalancing:::loadbalancer/foo'
    assert 'foo' == rgta.get_short_id_from_elb_arn(arn)


def test_get_short_id_from_lb2_arn():
    arn = 'arn:aws:elasticloadbalancing:::loadbalancer/app/foo/abdc123'
    assert 'foo' == rgta.get_short_id_from_lb2_arn(arn)


def test_transform_tags():
    get_resources_response = copy.deepcopy(test_data.GET_RESOURCES_RESPONSE)
    assert 'resource_id' not in get_resources_response[0]
    rgta.transform_tags(get_resources_response, 'ec2:instance')
    assert 'resource_id' in get_resources_response[0]


def test_mappings_reachable_from_account():
    """
    The default load query requires a direct (:AWSAccount)-[:RESOURCE]->
    edge. Sub-resources (ECS tasks/container instances, ELBV2 listeners) hang
    off their parent, so they must declare an explicit 'path' or their tags
    are fetched from AWS and silently dropped.
    """
    sub_resource_labels = {'ECSTask', 'ECSContainerInstance', 'ELBV2Listener'}
    for resource_type, mapping in rgta.TAG_RESOURCE_TYPE_MAPPINGS.items():
        if mapping['label'] in sub_resource_labels:
            assert 'path' in mapping, f"{resource_type} needs an explicit path"
            assert mapping['path'].startswith('-[:RESOURCE]->')


def test_elbv2_listener_mapping_matches_node_id():
    # ELBV2Listener nodes are created with id = ListenerArn, so the mapping
    # must key the full ARN on 'id' (no id_func shortening)
    for resource_type in ('elasticloadbalancing:listener/app', 'elasticloadbalancing:listener/net'):
        mapping = rgta.TAG_RESOURCE_TYPE_MAPPINGS[resource_type]
        assert mapping['property'] == 'id'
        assert 'id_func' not in mapping
        arn = 'arn:aws:elasticloadbalancing:us-east-1:1234:listener/app/foo/abc/def'
        assert rgta.compute_resource_id({'ResourceARN': arn}, resource_type) == arn


def test_get_hosted_zone_id_from_arn():
    arn = 'arn:aws:route53:::hostedzone/Z0ABCDEF'
    assert rgta.get_hosted_zone_id_from_arn(arn) == '/hostedzone/Z0ABCDEF'


def test_get_log_group_arn_with_wildcard():
    arn = 'arn:aws:logs:us-east-1:1234:log-group:/aws/lambda/foo'
    assert rgta.get_log_group_arn_with_wildcard(arn) == arn + ':*'
    assert rgta.get_log_group_arn_with_wildcard(arn + ':*') == arn + ':*'


def test_expanded_mappings_present():
    # phase-2 coverage additions — data stores, workloads, edge, AI/ML, governance
    expected = {
        'kinesis:stream': 'KinesisStream',
        'ec2:snapshot': 'EBSSnapshot',
        'ec2:image': 'EC2Image',
        'ec2:route-table': 'EC2RouteTable',
        'ec2:launch-template': 'LaunchTemplate',
        'ecs:service': 'ECSService',
        'eks:nodegroup': 'EKSClusterNodeGroup',
        'cloudformation:stack': 'AWSCloudformationStack',
        'cloudfront:distribution': 'AWSCloudfrontDistribution',
        'cloudtrail:trail': 'AWSCloudTrailTrail',
        'config:config-rule': 'AWSConfigRule',
        'logs:log-group': 'AWSCloudWatchLogGroup',
        'route53:hostedzone': 'AWSDNSZone',
        'ses:identity': 'AWSSESIdentity',
        'sns': 'AWSSNSTopic',
        'wafv2': 'AWSWAFv2WebACL',
        'waf-regional:webacl': 'AWSWAFClassicWebACL',
        'sagemaker:notebook-instance': 'AWSSagemakerNotebookInstance',
        'sagemaker:endpoint': 'AWSSagemakerEndpoint',
        'sagemaker:model': 'AWSSagemakerModel',
        'sagemaker:domain': 'AWSSagemakerDomain',
        'sagemaker:cluster': 'AWSSagemakerCluster',
        'sagemaker:training-job': 'AWSSagemakerTrainingJob',
        'bedrock:agent': 'AWSBedrockAgent',
        'bedrock:custom-model': 'AWSBedrockCustomModel',
        'bedrock:guardrail': 'AWSBedrockGuardRail',
        'bedrock:model-customization-job': 'AWSBedrockCustomisationJob',
    }
    for resource_type, label in expected.items():
        assert resource_type in rgta.TAG_RESOURCE_TYPE_MAPPINGS, resource_type
        assert rgta.TAG_RESOURCE_TYPE_MAPPINGS[resource_type]['label'] == label


def test_every_mapping_has_label_and_property():
    for resource_type, mapping in rgta.TAG_RESOURCE_TYPE_MAPPINGS.items():
        assert mapping.get('label'), resource_type
        assert mapping.get('property') in ('id', 'arn', 'name', 'subnetid', 'zoneid'), resource_type


def test_untaggable_types_removed():
    # ecs:container and classic elasticloadbalancing:listener are not taggable
    # resource types; keeping them only wasted API calls every sync
    assert 'ecs:container' not in rgta.TAG_RESOURCE_TYPE_MAPPINGS
    assert 'elasticloadbalancing:listener' not in rgta.TAG_RESOURCE_TYPE_MAPPINGS


def test_global_resource_types_synced_once_in_us_east_1(mocker, monkeypatch):
    """
    Global services (CloudFront, Route53) are reported by the tagging API only
    in us-east-1 — one sync per account, not one per region.
    """
    monkeypatch.setenv('LOCAL_RUN', '1')
    sync_tags = mocker.patch.object(rgta, 'sync_tags')
    mocker.patch.object(rgta, 'cleanup')
    mappings = {
        'sqs': {'label': 'SQSQueue', 'property': 'id'},
        'cloudfront:distribution': {'label': 'AWSCloudfrontDistribution', 'property': 'id'},
        'route53:hostedzone': {'label': 'AWSDNSZone', 'property': 'zoneid'},
    }

    rgta.sync(
        mocker.MagicMock(), mocker.MagicMock(), mocker.MagicMock(),
        ['us-east-1', 'eu-west-1'], '1234', 111, {},
        tag_resource_type_mappings=mappings,
    )

    calls = [(c.args[2], c.args[3]) for c in sync_tags.call_args_list]
    assert calls.count(('us-east-1', 'sqs')) == 1
    assert calls.count(('eu-west-1', 'sqs')) == 1
    assert [c for c in calls if c[1] == 'cloudfront:distribution'] == [('us-east-1', 'cloudfront:distribution')]
    assert [c for c in calls if c[1] == 'route53:hostedzone'] == [('us-east-1', 'route53:hostedzone')]


def test_load_query_uses_mapping_path(mocker):
    tx = mocker.MagicMock()
    tag_data = [{
        'ResourceARN': 'arn:aws:ecs:us-east-1:1234:task/cluster/abc',
        'resource_id': 'arn:aws:ecs:us-east-1:1234:task/cluster/abc',
        'Tags': [{'Key': 'k', 'Value': 'v'}],
    }]
    rgta._load_tags_tx(tx, tag_data, 'ecs:task', 'us-east-1', '1234', 111)
    query = tx.run.call_args[0][0]
    assert '-[:RESOURCE]->(:ECSCluster)-[:HAS_TASK]->(resource:ECSTask' in query

    rgta._load_tags_tx(tx, tag_data, 'ec2:instance', 'us-east-1', '1234', 111)
    query = tx.run.call_args[0][0]
    assert '-[res:RESOURCE]->(resource:EC2Instance' in query


def test_phase2_remainder_mappings_present():
    # remaining taggable types added after the first phase-2 batch
    expected = {
        'cloudwatch:alarm': 'AWSCloudWatchAlarm',
        'events:rule': 'AWSEventBridgeRule',
        'events:event-bus': 'AWSEventBridgeEventBus',
        'rds:ri': 'RDSReservedDBInstance',
        'ec2:reserved-instances': 'EC2ReservedInstance',
        'securityhub:hub': 'SecurityHub',
    }
    for resource_type, label in expected.items():
        assert resource_type in rgta.TAG_RESOURCE_TYPE_MAPPINGS, resource_type
        assert rgta.TAG_RESOURCE_TYPE_MAPPINGS[resource_type]['label'] == label


def test_reserved_instance_mapping_uses_short_id():
    # EC2ReservedInstance nodes are created with id = ReservedInstancesId, not the ARN
    arn = 'arn:aws:ec2:us-east-1:1234:reserved-instances/ri-abcd'
    assert rgta.compute_resource_id({'ResourceARN': arn}, 'ec2:reserved-instances') == 'ri-abcd'
