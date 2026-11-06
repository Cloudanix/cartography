"""A VPC attachment's VPC and subnet links reach only the syncing account's attachment."""
from cartography.intel.aws.ec2 import tgw
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
OWN, OTHER = 'ta-own', 'ta-other'


def test_vpc_attachment_links_stay_in_the_account(neo4j_session):
    create_test_org_account(neo4j_session, 'ta-ws-own', 'ta-org-own', OWN)
    create_test_org_account(neo4j_session, 'ta-ws-other', 'ta-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:AWSTransitGatewayAttachment{id: 'tgw-attach-ta-own'})
        MERGE (other)-[:RESOURCE]->(:AWSTransitGatewayAttachment{id: 'tgw-attach-ta-other'})
        """,
        own=OWN, other=OTHER,
    )

    for attachment in ('tgw-attach-ta-own', 'tgw-attach-ta-other'):
        tgw._attach_tgw_vpc_attachment_to_vpc_subnets(
            neo4j_session,
            {
                'TransitGatewayAttachmentId': attachment, 'VpcId': f'vpc-{attachment}',
                'SubnetIds': [f'subnet-{attachment}'],
            },
            REGION, OWN, TAG,
        )

    linked = neo4j_session.run(
        """
        MATCH (a:AWSTransitGatewayAttachment)-[r:PART_OF_SUBNET|RESOURCE]-(n) WHERE NOT n:AWSAccount
        RETURN a.id AS a, type(r) AS r
        """,
    )
    assert {(r['a'], r['r']) for r in linked} == {
        ('tgw-attach-ta-own', 'PART_OF_SUBNET'), ('tgw-attach-ta-own', 'RESOURCE'),
    }


def _gateway(owner, tgw_id):
    return {
        'TransitGatewayId': tgw_id, 'TransitGatewayArn': f'arn:aws:ec2:{REGION}:{owner}:transit-gateway/{tgw_id}',
        'OwnerId': owner, 'State': 'available',
    }


def _attached_gateways(neo4j_session, attachment_id):
    rows = neo4j_session.run(
        "MATCH (:AWSTransitGatewayAttachment{id: $id})-[:ATTACHED_TO]->(t:AWSTransitGateway) RETURN t.arn AS arn",
        id=attachment_id,
    )
    return {r['arn'] for r in rows}


def test_attachment_links_only_to_an_owned_or_shared_gateway(neo4j_session):
    own, sharer, other = 'tg-own', 'tg-sharer', 'tg-other'
    create_test_org_account(neo4j_session, 'tg-ws-own', 'tg-org-own', own)
    create_test_org_account(neo4j_session, 'tg-ws-other', 'tg-org-other', other)
    # Another customer's gateways, one of them with the id of this account's own gateway.
    tgw.load_transit_gateways(
        neo4j_session, [_gateway(other, 'tgw-tg-dup'), _gateway(other, 'tgw-tg-foreign')], REGION, other, TAG,
    )
    # This account owns tgw-tg-dup and has tgw-tg-shared RAM-shared into it by an unsynced account.
    tgw.load_transit_gateways(
        neo4j_session, [_gateway(own, 'tgw-tg-dup'), _gateway(sharer, 'tgw-tg-shared')], REGION, own, TAG,
    )

    tgw.load_tgw_attachments(
        neo4j_session,
        [
            {
                'TransitGatewayAttachmentId': f'tgw-attach-tg-{name}', 'TransitGatewayId': f'tgw-tg-{name}',
                'State': 'available', 'ResourceType': 'vpn',
            }
            for name in ('dup', 'shared', 'foreign')
        ],
        REGION, own, TAG,
    )

    def arn(owner, tgw_id):
        return f'arn:aws:ec2:{REGION}:{owner}:transit-gateway/{tgw_id}'

    assert _attached_gateways(neo4j_session, 'tgw-attach-tg-dup') == {arn(own, 'tgw-tg-dup')}
    assert _attached_gateways(neo4j_session, 'tgw-attach-tg-shared') == {arn(sharer, 'tgw-tg-shared')}
    assert _attached_gateways(neo4j_session, 'tgw-attach-tg-foreign') == set()
