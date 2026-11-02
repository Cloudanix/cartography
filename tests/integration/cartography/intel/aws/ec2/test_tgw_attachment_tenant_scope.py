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
