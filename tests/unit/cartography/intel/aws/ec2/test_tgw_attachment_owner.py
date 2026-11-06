import pytest

from cartography.intel.aws.ec2 import tgw

ME, OTHER = '111111111111', '222222222222'


@pytest.mark.parametrize(
    'attachment, foreign', [
        # describe_transit_gateway_vpc_attachments: VpcOwnerId, no ResourceType
        ({'VpcOwnerId': OTHER}, True),
        ({'VpcOwnerId': ME}, False),
        # owned by the attached resource's owner
        ({'ResourceType': 'vpc', 'ResourceOwnerId': OTHER, 'TransitGatewayOwnerId': ME}, True),
        ({'ResourceType': 'connect', 'ResourceOwnerId': OTHER, 'TransitGatewayOwnerId': ME}, True),
        ({'ResourceType': 'connect', 'ResourceOwnerId': ME, 'TransitGatewayOwnerId': OTHER}, False),
        # owned by the gateway owner, whoever owns the far end
        ({'ResourceType': 'vpn', 'ResourceOwnerId': OTHER, 'TransitGatewayOwnerId': OTHER}, True),
        ({'ResourceType': 'direct-connect-gateway', 'ResourceOwnerId': OTHER, 'TransitGatewayOwnerId': ME}, False),
        ({'ResourceType': 'network-function', 'TransitGatewayOwnerId': OTHER}, True),
        # no reliable owner: kept as before
        ({'ResourceType': 'peering', 'ResourceOwnerId': OTHER, 'TransitGatewayOwnerId': OTHER}, False),
        ({'ResourceType': 'client-vpn', 'ResourceOwnerId': OTHER}, False),
        ({}, False),
    ],
)
def test_is_foreign_attachment(attachment, foreign):
    assert tgw._is_foreign_attachment(attachment, ME) is foreign
