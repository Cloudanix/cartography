"""Security group, subnet and CIDR block links to a VPC stay inside the workspace."""
from cartography.intel.aws.ec2 import security_groups
from cartography.intel.aws.ec2 import subnets
from cartography.intel.aws.ec2 import vpc
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
# OWN and SIBLING belong to one workspace, OTHER to another customer.
OWN, SIBLING, OTHER = 'vl-own', 'vl-sibling', 'vl-other'
WORKSPACE = 'vl-ws'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, WORKSPACE, 'vl-org', OWN)
    create_test_org_account(neo4j_session, WORKSPACE, 'vl-org', SIBLING)
    create_test_org_account(neo4j_session, 'vl-ws-other', 'vl-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (sibling:AWSAccount{id: $sibling}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:AWSVpc{id: 'vpc-vl-own'})
        MERGE (sibling)-[:RESOURCE]->(:AWSVpc{id: 'vpc-vl-sibling'})
        MERGE (sibling)-[:RESOURCE]->(:EC2Subnet{subnetid: 'subnet-vl-sibling'})
        MERGE (other)-[:RESOURCE]->(:AWSVpc{id: 'vpc-vl-other'})
        MERGE (other)-[:RESOURCE]->(:EC2Subnet{subnetid: 'subnet-vl-other'})
        """,
        own=OWN, sibling=SIBLING, other=OTHER,
    )


def _members(neo4j_session, label, key, rel):
    return {
        (r['n'], r['v']) for r in neo4j_session.run(
            f"MATCH (n:{label})-[:{rel}]-(v:AWSVpc) RETURN n.{key} AS n, v.id AS v",
        )
    }


def test_security_groups_join_only_vpcs_of_the_workspace(neo4j_session):
    _seed(neo4j_session)
    groups = [
        {'GroupId': f'sg-vl-{name}', 'GroupName': name, 'VpcId': f'vpc-vl-{name}', 'region': REGION}
        for name in ('own', 'sibling', 'other')
    ]

    security_groups.load_ec2_security_groupinfo(neo4j_session, groups, OWN, TAG, WORKSPACE)

    assert _members(neo4j_session, 'EC2SecurityGroup', 'id', 'MEMBER_OF_EC2_SECURITY_GROUP') == {
        ('sg-vl-own', 'vpc-vl-own'), ('sg-vl-sibling', 'vpc-vl-sibling'),
    }


def test_subnets_join_only_vpcs_of_the_workspace(neo4j_session):
    _seed(neo4j_session)
    rows = [
        {'SubnetId': 'subnet-vl-own', 'VpcId': 'vpc-vl-own', 'OwnerId': OWN},
        # this account's subnet naming a VPC id it does not own
        {'SubnetId': 'subnet-vl-stray', 'VpcId': 'vpc-vl-other', 'OwnerId': OWN},
        # subnets shared in through RAM: by an account of the workspace, and by another customer
        {'SubnetId': 'subnet-vl-sibling', 'VpcId': 'vpc-vl-sibling', 'OwnerId': SIBLING},
        {'SubnetId': 'subnet-vl-other', 'VpcId': 'vpc-vl-other', 'OwnerId': OTHER},
    ]

    subnets.load_subnets(neo4j_session, rows, OWN, TAG, WORKSPACE)

    assert _members(neo4j_session, 'EC2Subnet', 'subnetid', 'MEMBER_OF_AWS_VPC') == {
        ('subnet-vl-own', 'vpc-vl-own'), ('subnet-vl-sibling', 'vpc-vl-sibling'),
    }


def test_cidr_blocks_are_written_only_on_the_accounts_vpc(neo4j_session):
    _seed(neo4j_session)
    vpcs = [
        {
            'VpcId': vpc_id, 'OwnerId': owner, 'region': REGION, 'CidrBlock': '10.0.0.0/16',
            'CidrBlockAssociationSet': [{'AssociationId': f'{vpc_id}-assoc', 'CidrBlock': '10.0.0.0/16'}],
        }
        for vpc_id, owner in (('vpc-vl-own', OWN), ('vpc-vl-other', OTHER))
    ]

    vpc.load_ec2_vpcs(neo4j_session, vpcs, OWN, TAG)

    blocks = neo4j_session.run("MATCH (v:AWSVpc)-[:BLOCK_ASSOCIATION]->(:AWSCidrBlock) RETURN v.id AS v")
    assert [r['v'] for r in blocks] == ['vpc-vl-own']
