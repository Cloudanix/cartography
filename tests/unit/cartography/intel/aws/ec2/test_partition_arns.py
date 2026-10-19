import datetime
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from cartography.intel.aws.ec2 import elastic_ip_addresses
from cartography.intel.aws.ec2 import images
from cartography.intel.aws.ec2 import instances
from cartography.intel.aws.ec2 import internet_gateways
from cartography.intel.aws.ec2 import key_pairs
from cartography.intel.aws.ec2 import launch_templates
from cartography.intel.aws.ec2 import load_balancers
from cartography.intel.aws.ec2 import network_interfaces
from cartography.intel.aws.ec2 import reserved_instances
from cartography.intel.aws.ec2 import route_tables
from cartography.intel.aws.ec2 import security_groups
from cartography.intel.aws.ec2 import snapshots
from cartography.intel.aws.ec2 import tgw
from cartography.intel.aws.ec2 import volumes
from cartography.intel.aws.ec2 import vpc
from cartography.intel.aws.ec2 import vpc_peerings

ACCOUNT = '123456789012'
NOW = datetime.datetime(2024, 1, 1)

# (partition kwargs, region, expected ARN prefix). No kwargs keeps the historical arn:aws: form.
PARTITION_CASES = [
    ({}, 'us-east-1', 'arn:aws:'),
    ({'partition': 'aws-us-gov'}, 'us-gov-west-1', 'arn:aws-us-gov:'),
    ({'partition': 'aws-cn'}, 'cn-north-1', 'arn:aws-cn:'),
]


def _rows(load_graph_data: MagicMock) -> list:
    """The DictList passed to the first load_graph_data(session, query, rows, ...) call."""
    return load_graph_data.call_args_list[0].args[2]


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
def test_transform_volumes(kwargs, region, prefix):
    out = volumes.transform_volumes([{'VolumeId': 'vol-1'}], region, ACCOUNT, **kwargs)
    assert out[0]['Arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:volume/vol-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
def test_transform_elastic_ip_addresses(kwargs, region, prefix):
    address = {'AllocationId': 'eipalloc-1', 'PublicIp': '8.8.8.8', 'region': region}
    out = elastic_ip_addresses.transform_elastic_ip_addresses([address], ACCOUNT, **kwargs)
    assert out[0]['arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:elastic-ip/eipalloc-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
def test_transform_network_interface_data(kwargs, region, prefix):
    eni = {'NetworkInterfaceId': 'eni-1', 'Description': '', 'InterfaceType': 'interface', 'MacAddress': 'm'}
    out = network_interfaces.transform_network_interface_data([eni], region, ACCOUNT, **kwargs)
    assert out.network_interface_list[0]['Arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:network-interface/eni-1'
    legacy = network_interfaces.transform_network_interfaces(
        [{'NetworkInterfaceId': 'eni-1'}], region, ACCOUNT, **kwargs,
    )
    assert legacy[0]['Arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:network-interface/eni-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
def test_transform_ec2_instances(kwargs, region, prefix):
    reservation = {
        'ReservationId': 'r-1', 'OwnerId': ACCOUNT,
        'Instances': [{'InstanceId': 'i-1', 'KeyName': 'k1', 'NetworkInterfaces': []}],
    }
    out = instances.transform_ec2_instances(MagicMock(), [reservation], region, ACCOUNT, **kwargs)
    assert out.instance_list[0]['arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:instance/i-1'
    assert out.keypair_list[0]['KeyPairArn'] == f'{prefix}ec2:{region}:{ACCOUNT}:key-pair/k1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(snapshots, 'load_graph_data')
def test_load_snapshots(load_graph_data, kwargs, region, prefix):
    data = [{'SnapshotId': 'snap-1', 'StartTime': NOW, 'region': region}]
    snapshots.load_snapshots(MagicMock(), data, ACCOUNT, 1, **kwargs)
    assert _rows(load_graph_data)[0]['Arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:snapshot/snap-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(reserved_instances, 'load_graph_data')
def test_load_reserved_instances(load_graph_data, kwargs, region, prefix):
    data = [{'ReservedInstancesId': 'ri-1', 'Start': NOW, 'End': NOW}]
    reserved_instances.load_reserved_instances(MagicMock(), data, region, ACCOUNT, 1, **kwargs)
    assert _rows(load_graph_data)[0]['Arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:reserved-instances/ri-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(security_groups, 'load_ec2_security_group_rules')
@patch.object(security_groups, 'load_graph_data')
def test_load_ec2_security_groupinfo(load_graph_data, _rules, kwargs, region, prefix):
    data = [{'GroupId': 'sg-1', 'region': region}]
    security_groups.load_ec2_security_groupinfo(MagicMock(), data, ACCOUNT, 1, **kwargs)
    assert _rows(load_graph_data)[0]['group_arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:security-group/sg-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(vpc_peerings, 'load_graph_data')
def test_load_vpc_peerings(load_graph_data, kwargs, region, prefix):
    data = [{'VpcPeeringConnectionId': 'pcx-1'}]
    vpc_peerings.load_vpc_peerings(MagicMock(), data, region, ACCOUNT, 1, **kwargs)
    assert _rows(load_graph_data)[0]['arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:vpc-peering-connection/pcx-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(images, 'load_graph_data')
def test_load_images(load_graph_data, kwargs, region, prefix):
    data = [{'ImageId': 'ami-1', 'region': region}]
    images.load_images(MagicMock(), data, ACCOUNT, 1, **kwargs)
    assert _rows(load_graph_data)[0]['arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:image/ami-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(load_balancers, 'load_load_balancer_listeners')
@patch.object(load_balancers, 'load_load_balancer_subnets')
@patch.object(load_balancers, 'load_graph_data')
def test_load_load_balancers(load_graph_data, _subnets, _listeners, kwargs, region, prefix):
    lb = {
        'DNSName': 'lb-1.elb.amazonaws.com', 'LoadBalancerName': 'lb-1', 'CreatedTime': NOW, 'region': region,
        'Subnets': [], 'SecurityGroups': [], 'SourceSecurityGroup': None, 'Instances': [],
        'ListenerDescriptions': [],
    }
    load_balancers.load_load_balancers(MagicMock(), [lb], ACCOUNT, 1, **kwargs)
    assert _rows(load_graph_data)[0]['arn'] == \
        f'{prefix}elasticloadbalancing:{region}:{ACCOUNT}:loadbalancer/lb-1.elb.amazonaws.com'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
def test_load_route_tables(kwargs, region, prefix):
    data = [{'RouteTableId': 'rtb-1', 'region': region, 'Associations': [], 'Routes': []}]
    route_tables.load_route_tables(MagicMock(), data, ACCOUNT, 1, **kwargs)
    assert data[0]['arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:route-table/rtb-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(vpc, 'load_cidr_association_set')
@patch.object(vpc, 'run_write_query')
def test_load_ec2_vpcs(run_write_query, _cidrs, kwargs, region, prefix):
    vpc.load_ec2_vpcs(MagicMock(), [{'VpcId': 'vpc-1', 'region': region}], ACCOUNT, 1, **kwargs)
    assert run_write_query.call_args.kwargs['Arn'] == f'{prefix}ec2:{region}:{ACCOUNT}:vpc/vpc-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(tgw, 'run_write_query')
def test_load_tgw_attachments(run_write_query, kwargs, region, prefix):
    data = [{'TransitGatewayAttachmentId': 'tgw-attach-1', 'TransitGatewayId': 'tgw-1', 'State': 'available'}]
    tgw.load_tgw_attachments(MagicMock(), data, region, ACCOUNT, 1, **kwargs)
    assert run_write_query.call_args.kwargs['Arn'] == \
        f'{prefix}ec2:{region}:{ACCOUNT}:transit-gateway-attachment/tgw-attach-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(key_pairs, 'run_write_query')
def test_load_ec2_key_pairs(run_write_query, kwargs, region, prefix):
    key_pairs.load_ec2_key_pairs(MagicMock(), [{'KeyName': 'k1', 'region': region}], ACCOUNT, 1, **kwargs)
    assert run_write_query.call_args.kwargs['ARN'] == f'{prefix}ec2:{region}:{ACCOUNT}:key-pair/k1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(launch_templates, 'load_graph_data')
@patch.object(launch_templates, 'aws_console_link')
def test_load_launch_templates_console_arn(console_link, _load, kwargs, region, prefix):
    data = [{'LaunchTemplateId': 'lt-1', 'CreateTime': NOW}]
    launch_templates.load_launch_templates(MagicMock(), data, region, ACCOUNT, 1, **kwargs)
    assert console_link.get_console_link.call_args.kwargs['arn'] == \
        f'{prefix}ec2:{region}:{ACCOUNT}:launch-template/lt-1'


@pytest.mark.parametrize('kwargs, region, prefix', PARTITION_CASES)
@patch.object(internet_gateways, 'load_graph_data')
def test_load_internet_gateways_passes_partition_to_cypher(load_graph_data, kwargs, region, prefix):
    igw = {'InternetGatewayId': 'igw-1', 'OwnerId': ACCOUNT}
    internet_gateways.load_internet_gateways(MagicMock(), [igw], region, ACCOUNT, 1, **kwargs)
    # ig.arn is assembled in Cypher as "arn:" + $partition + ":ec2:" + ...
    assert load_graph_data.call_args.kwargs['partition'] == prefix[len('arn:'):-1]


@patch.object(vpc, 'cleanup_ec2_vpcs')
@patch.object(vpc, 'load_ec2_vpcs')
@patch.object(vpc, 'get_ec2_vpcs', return_value=[])
def test_sync_vpc_threads_partition_from_common_job_parameters(_get, load_ec2_vpcs, _cleanup):
    vpc.sync_vpc(MagicMock(), MagicMock(), ['cn-north-1'], ACCOUNT, 1, {'AWS_PARTITION': 'aws-cn'})
    assert load_ec2_vpcs.call_args.kwargs['partition'] == 'aws-cn'
