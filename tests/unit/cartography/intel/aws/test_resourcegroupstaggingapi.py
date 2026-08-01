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


def test_untaggable_types_removed():
    # ecs:container and classic elasticloadbalancing:listener are not taggable
    # resource types; keeping them only wasted API calls every sync
    assert 'ecs:container' not in rgta.TAG_RESOURCE_TYPE_MAPPINGS
    assert 'elasticloadbalancing:listener' not in rgta.TAG_RESOURCE_TYPE_MAPPINGS


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
