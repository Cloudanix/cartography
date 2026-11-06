"""ENI IPv6 addresses feed the ::/0 statement of aws_ec2_instance_asset_exposure.json: an instance is
reachable over IPv6 only when it, or an attached ENI, holds an IPv6 address."""
from unittest.mock import MagicMock

from cartography.intel.aws.ec2 import instances
from cartography.intel.aws.ec2 import network_interfaces

ACCOUNT = '123456789012'
REGION = 'us-east-1'
ENI = {'NetworkInterfaceId': 'eni-1', 'Description': '', 'InterfaceType': 'interface', 'MacAddress': 'm'}


def _eni_rows(**extra) -> list:
    out = network_interfaces.transform_network_interface_data([{**ENI, **extra}], REGION, ACCOUNT)
    return out.network_interface_list


def test_network_interface_ipv6_addresses():
    rows = _eni_rows(Ipv6Addresses=[{'Ipv6Address': '2600:1f18::1'}, {'Ipv6Address': '2600:1f18::2'}])
    assert rows[0]['Ipv6Addresses'] == ['2600:1f18::1', '2600:1f18::2']


def test_network_interface_without_ipv6_is_empty_list():
    assert _eni_rows()[0]['Ipv6Addresses'] == []
    assert _eni_rows(Ipv6Addresses=[])[0]['Ipv6Addresses'] == []


def _instance_eni_rows(nic: dict) -> list:
    reservation = {
        'ReservationId': 'r-1', 'OwnerId': ACCOUNT,
        'Instances': [{'InstanceId': 'i-1', 'NetworkInterfaces': [nic]}],
    }
    return instances.transform_ec2_instances(MagicMock(), [reservation], REGION, ACCOUNT).network_interface_list


def test_instance_network_interface_ipv6_addresses():
    nic = {
        'NetworkInterfaceId': 'eni-1', 'Status': 'in-use', 'MacAddress': 'm', 'Description': '',
        'Groups': [{'GroupId': 'sg-1'}], 'Ipv6Addresses': [{'Ipv6Address': '2600:1f18::1'}],
    }
    assert _instance_eni_rows(nic)[0]['Ipv6Addresses'] == ['2600:1f18::1']


def test_instance_network_interface_without_ipv6_is_empty_list():
    nic = {
        'NetworkInterfaceId': 'eni-1', 'Status': 'in-use', 'MacAddress': 'm', 'Description': '',
        'Groups': [{'GroupId': 'sg-1'}],
    }
    assert _instance_eni_rows(nic)[0]['Ipv6Addresses'] == []
