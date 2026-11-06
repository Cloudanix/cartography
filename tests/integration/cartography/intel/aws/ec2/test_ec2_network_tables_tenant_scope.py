"""Network ACL and route table rules, associations and VPC links stay inside the syncing account."""
from cartography.intel.aws.ec2 import network_acls
from cartography.intel.aws.ec2 import route_tables
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
OWN, OTHER = 'nt-own', 'nt-other'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, 'nt-ws-own', 'nt-org-own', OWN)
    create_test_org_account(neo4j_session, 'nt-ws-other', 'nt-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:AWSVpc{id: 'vpc-nt-own'})
        MERGE (other)-[:RESOURCE]->(:AWSVpc{id: 'vpc-nt-other'})
        MERGE (other)-[:RESOURCE]->(:EC2NetworkAcl{id: 'acl-nt-other'})
        MERGE (other)-[:RESOURCE]->(:EC2RouteTable{id: 'rtb-nt-other'})
        """,
        own=OWN, other=OTHER,
    )


def _out(neo4j_session, node_id):
    return {
        r['type'] for r in neo4j_session.run(
            "MATCH ({id: $id})-[r]-(n) WHERE NOT n:AWSAccount RETURN type(r) AS type", id=node_id,
        )
    }


def test_network_acl_links_stay_in_the_account(neo4j_session):
    _seed(neo4j_session)
    acls = [
        {'id': 'acl-nt-own', 'arn': 'a1', 'is_default': False, 'vpc_id': 'vpc-nt-own', 'region': REGION},
        {'id': 'acl-nt-stray', 'arn': 'a2', 'is_default': False, 'vpc_id': 'vpc-nt-other', 'region': REGION},
    ]
    rules = [
        {'id': f'{acl}/inbound/100', 'acl_id': acl, 'rule_number': 100} for acl in ('acl-nt-own', 'acl-nt-other')
    ]
    assocs = [{'acl_id': acl, 'subnet_id': f'subnet-{acl}'} for acl in ('acl-nt-own', 'acl-nt-other')]

    network_acls.load_network_acls(neo4j_session, acls, rules, assocs, OWN, TAG)

    assert _out(neo4j_session, 'acl-nt-own') == {'MEMBER_OF_AWS_VPC', 'MEMBER_OF_NACL', 'PART_OF_SUBNET'}
    assert _out(neo4j_session, 'acl-nt-stray') == set()
    assert _out(neo4j_session, 'acl-nt-other') == set()


def test_route_table_links_stay_in_the_account(neo4j_session):
    _seed(neo4j_session)
    tables = [
        {
            'RouteTableId': rtb, 'VpcId': vpc, 'OwnerId': OWN, 'region': REGION,
            'Routes': [{'DestinationCidrBlock': '0.0.0.0/0', 'GatewayId': 'igw-1'}],
            'Associations': [{'RouteTableAssociationId': f'{rtb}-assoc', 'RouteTableId': rtb, 'SubnetId': 'subnet-1'}],
        }
        for rtb, vpc in (('rtb-nt-own', 'vpc-nt-own'), ('rtb-nt-stray', 'vpc-nt-other'))
    ]
    route_tables.load_route_tables(neo4j_session, tables, OWN, TAG)
    # rows naming another customer's route table
    neo4j_session.execute_write(
        route_tables.load_routes_tx,
        [{'id': 'route-nt-x', 'RouteTableId': 'rtb-nt-other', 'DestinationCidrBlock': '0.0.0.0/0'}], OWN, TAG,
    )
    neo4j_session.execute_write(
        route_tables.load_associations_tx,
        [{'RouteTableAssociationId': 'assoc-nt-x', 'RouteTableId': 'rtb-nt-other'}], OWN, TAG,
    )

    assert _out(neo4j_session, 'rtb-nt-own') == {'MEMBER_OF_AWS_VPC', 'MEMBER_OF_ROUTE_TABLE', 'HAS_ASSOCIATION'}
    assert 'MEMBER_OF_AWS_VPC' not in _out(neo4j_session, 'rtb-nt-stray')
    assert _out(neo4j_session, 'rtb-nt-other') == set()
