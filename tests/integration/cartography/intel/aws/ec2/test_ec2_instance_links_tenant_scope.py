"""Instance -> image, instance -> role and internet gateway -> VPC links stay inside the tenant."""
from cartography.intel.aws.ec2 import images
from cartography.intel.aws.ec2 import instances
from cartography.intel.aws.ec2 import internet_gateways
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
# OWN and SIBLING belong to one workspace, OTHER to another customer.
OWN, SIBLING, OTHER = 'il-own', 'il-sibling', 'il-other'
WORKSPACE = 'il-ws'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, WORKSPACE, 'il-org', OWN)
    create_test_org_account(neo4j_session, WORKSPACE, 'il-org', SIBLING)
    create_test_org_account(neo4j_session, 'il-ws-other', 'il-org-other', OTHER)


def test_instances_link_only_to_their_own_accounts_image(neo4j_session):
    _seed(neo4j_session)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:EC2Image{id: 'ami-il|us-east-1', imageid: 'ami-il'})
        MERGE (own)-[:RESOURCE]->(:EC2Instance{id: 'i-il-own', imageid: 'ami-il'})
        MERGE (other)-[:RESOURCE]->(:EC2Instance{id: 'i-il-other', imageid: 'ami-il'})
        """,
        own=OWN, other=OTHER,
    )

    images.link_ec2_instances_to_images(neo4j_session, OWN, TAG)

    linked = neo4j_session.run("MATCH (i:EC2Instance)-[:CHILDREN]->(:EC2Image) RETURN i.id AS id")
    assert [r['id'] for r in linked] == ['i-il-own']


def test_instance_roles_link_only_inside_the_account(neo4j_session):
    _seed(neo4j_session)
    own_role, other_role = f'arn:aws:iam::{OWN}:role/r', f'arn:aws:iam::{OTHER}:role/r'
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:EC2Instance{id: 'i-ir-own'})
        MERGE (own)-[:RESOURCE]->(:AWSRole{arn: $own_role})
        MERGE (other)-[:RESOURCE]->(:EC2Instance{id: 'i-ir-other'})
        MERGE (other)-[:RESOURCE]->(:AWSRole{arn: $other_role})
        """,
        own=OWN, other=OTHER, own_role=own_role, other_role=other_role,
    )

    instances.load_ec2_roles(
        neo4j_session,
        [
            {'InstanceId': 'i-ir-own', 'Arn': own_role},
            {'InstanceId': 'i-ir-other', 'Arn': own_role},
            {'InstanceId': 'i-ir-own', 'Arn': other_role},
        ],
        REGION, OWN, TAG,
    )

    uses = neo4j_session.run("MATCH (i:EC2Instance)-[:USES]->(r:AWSRole) RETURN i.id AS i, r.arn AS r")
    assert {(r['i'], r['r']) for r in uses} == {('i-ir-own', own_role)}


def _igw(igw_id, owner, vpc_id):
    return {'InternetGatewayId': igw_id, 'OwnerId': owner, 'Attachments': [{'VpcId': vpc_id}]}


def test_internet_gateways_attach_only_to_vpcs_of_the_workspace(neo4j_session):
    _seed(neo4j_session)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (sibling:AWSAccount{id: $sibling}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:AWSVpc{id: 'vpc-il-own'})
        MERGE (sibling)-[:RESOURCE]->(:AWSVpc{id: 'vpc-il-sibling'})
        MERGE (other)-[:RESOURCE]->(:AWSVpc{id: 'vpc-il-other'})
        """,
        own=OWN, sibling=SIBLING, other=OTHER,
    )
    gateways = [
        _igw('igw-il-own', OWN, 'vpc-il-own'),
        # this account's gateway naming a VPC id it does not own
        _igw('igw-il-stray', OWN, 'vpc-il-other'),
        # gateways of VPCs shared into this account (RAM): same workspace, and another customer
        _igw('igw-il-sibling', SIBLING, 'vpc-il-sibling'),
        _igw('igw-il-foreign', OTHER, 'vpc-il-other'),
    ]

    internet_gateways.load_internet_gateways(neo4j_session, gateways, REGION, OWN, TAG, WORKSPACE)

    attached = neo4j_session.run(
        "MATCH (v:AWSVpc)-[:ATTACHED_TO]->(ig:AWSInternetGateway) RETURN v.id AS v, ig.id AS ig",
    )
    assert {(r['v'], r['ig']) for r in attached} == {
        ('vpc-il-own', 'igw-il-own'), ('vpc-il-sibling', 'igw-il-sibling'),
    }
