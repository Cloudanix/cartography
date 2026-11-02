from importlib.resources import read_text

from cartography.graph.job import GraphJob
from cartography.intel.aws.ec2 import internet_gateways
from cartography.intel.aws.ec2 import subnets
from cartography.intel.aws.ec2 import vpc
from tests.integration.cartography.intel.aws.common import create_test_org_account

REGION = 'us-east-1'
OWNER_TAG, PARTICIPANT_TAG = 100, 200
# A VPC owner and a participant of another workspace the VPC is shared with (RAM).
OWNER, PARTICIPANT = 'sv-owner', 'sv-participant'


def _seed_accounts(neo4j_session):
    create_test_org_account(neo4j_session, 'sv-ws-owner', 'sv-ws-owner-org', OWNER)
    create_test_org_account(neo4j_session, 'sv-ws-participant', 'sv-ws-participant-org', PARTICIPANT)


def _vpc(vpc_id, tags):
    return {
        'VpcId': vpc_id, 'OwnerId': OWNER, 'region': REGION, 'State': 'available', 'CidrBlock': '10.1.0.0/16',
        'IsDefault': False, 'isDefault': False, 'Tags': tags,
        'CidrBlockAssociationSet': [{'AssociationId': f'{vpc_id}-assoc', 'CidrBlock': '10.1.0.0/16'}],
    }


def _igw(igw_id, vpc_id, is_default):
    return {
        'InternetGatewayId': igw_id, 'OwnerId': OWNER, 'isDefault': is_default,
        'Attachments': [{'VpcId': vpc_id, 'State': 'available'}],
    }


def _sync(neo4j_session, account_id, update_tag, vpcs, igws):
    vpc.load_ec2_vpcs(neo4j_session, vpcs, account_id, update_tag)
    internet_gateways.load_internet_gateways(neo4j_session, igws, REGION, account_id, update_tag)
    for job in ('aws_import_vpc_cleanup.json', 'aws_import_internet_gateways_cleanup.json'):
        GraphJob.run_from_json(
            neo4j_session, read_text('cartography.data.jobs.cleanup', job), {
                'WORKSPACE_ID': f'sv-ws-{account_id[3:]}', 'ORGANIZATION_ID': f'sv-ws-{account_id[3:]}-org',
                'AWS_ID': account_id, 'UPDATE_TAG': update_tag, 'LIMIT_SIZE': 100,
            },
        )


def _claims(neo4j_session, node_id):
    return {
        r['id'] for r in neo4j_session.run(
            "MATCH (a:AWSAccount)-[:RESOURCE]->({id: $id}) RETURN a.id AS id", id=node_id,
        )
    }


def test_shared_vpc_and_gateway_are_claimed_and_written_by_their_owner_only(neo4j_session):
    _seed_accounts(neo4j_session)
    _sync(
        neo4j_session, OWNER, OWNER_TAG,
        [_vpc('vpc-sv-1', [{'Key': 'Name', 'Value': 'prod'}])], [_igw('igw-sv-1', 'vpc-sv-1', True)],
    )
    # The participant sees the VPC without the owner's tags, and the gateway not as its default one.
    _sync(neo4j_session, PARTICIPANT, PARTICIPANT_TAG, [_vpc('vpc-sv-1', [])], [_igw('igw-sv-1', 'vpc-sv-1', False)])

    assert _claims(neo4j_session, 'vpc-sv-1') == {OWNER}
    assert _claims(neo4j_session, 'igw-sv-1') == {OWNER}
    shared = neo4j_session.run(
        """
        MATCH (v:AWSVpc{id: 'vpc-sv-1'})-[:ATTACHED_TO]->(ig:AWSInternetGateway{id: 'igw-sv-1'})
        RETURN v.name AS name, v.arn AS arn, v.lastupdated AS vpc_tag, ig.is_default AS is_default,
            ig.lastupdated AS igw_tag
        """,
    ).single()
    assert dict(shared) == {
        'name': 'prod', 'arn': f'arn:aws:ec2:{REGION}:{OWNER}:vpc/vpc-sv-1', 'vpc_tag': OWNER_TAG,
        'is_default': True, 'igw_tag': OWNER_TAG,
    }


def test_participant_sync_drops_its_old_claims_without_deleting_the_owners_nodes(neo4j_session):
    # Graph as the old loader left it: the participant synced last, so it holds RESOURCE edges and its own
    # arn on the owner's VPC.
    _seed_accounts(neo4j_session)
    neo4j_session.run(
        """
        MATCH (o:AWSAccount{id: $owner}), (p:AWSAccount{id: $participant})
        MERGE (v:AWSVpc{id: 'vpc-sv-2'})
        SET v.arn = $stamped_arn, v.lastupdated = 1
        MERGE (ig:AWSInternetGateway{id: 'igw-sv-2'})
        SET ig.ownerid = $owner, ig.lastupdated = 1
        MERGE (v)-[:ATTACHED_TO]->(ig)
        MERGE (o)-[:RESOURCE{lastupdated: 1}]->(v)
        MERGE (p)-[:RESOURCE{lastupdated: 1}]->(v)
        MERGE (o)-[:RESOURCE{lastupdated: 1}]->(ig)
        MERGE (p)-[:RESOURCE{lastupdated: 1}]->(ig)
        """,
        owner=OWNER, participant=PARTICIPANT, stamped_arn=f'arn:aws:ec2:{REGION}:{PARTICIPANT}:vpc/vpc-sv-2',
    )

    _sync(neo4j_session, PARTICIPANT, PARTICIPANT_TAG, [_vpc('vpc-sv-2', [])], [_igw('igw-sv-2', 'vpc-sv-2', False)])

    assert _claims(neo4j_session, 'vpc-sv-2') == {OWNER}
    assert _claims(neo4j_session, 'igw-sv-2') == {OWNER}


def _subnet(is_default):
    return {
        'SubnetId': 'subnet-sv-1', 'OwnerId': OWNER, 'VpcId': 'vpc-sv-3', 'CidrBlock': '10.3.0.0/24',
        'SubnetArn': f'arn:aws:ec2:{REGION}:{OWNER}:subnet/subnet-sv-1', 'region': REGION,
        'isDefault': is_default, 'consolelink': '',
    }


def _subnet_claims(neo4j_session):
    return {
        r['id'] for r in neo4j_session.run(
            "MATCH (a:AWSAccount)-[:RESOURCE]->(:EC2Subnet{subnetid: 'subnet-sv-1'}) RETURN a.id AS id",
        )
    }


def test_shared_subnet_is_claimed_and_written_by_its_owner_only(neo4j_session):
    _seed_accounts(neo4j_session)
    neo4j_session.run(
        """
        MATCH (o:AWSAccount{id: $owner}), (p:AWSAccount{id: $participant})
        MERGE (o)-[:RESOURCE]->(:AWSVpc{id: 'vpc-sv-3'})
        // the participant's claim from the old loader
        MERGE (s:EC2Subnet{subnetid: 'subnet-sv-1'})
        MERGE (p)-[:RESOURCE{lastupdated: 1}]->(s)
        """,
        owner=OWNER, participant=PARTICIPANT,
    )
    subnets.load_subnets(neo4j_session, [_subnet(True)], OWNER, OWNER_TAG)
    # The participant sees the subnet, not as part of its own default VPC.
    subnets.load_subnets(neo4j_session, [_subnet(False)], PARTICIPANT, PARTICIPANT_TAG)
    GraphJob.run_from_json(
        neo4j_session, read_text('cartography.data.jobs.cleanup', 'aws_ingest_subnets_cleanup.json'), {
            'WORKSPACE_ID': 'sv-ws-participant', 'ORGANIZATION_ID': 'sv-ws-participant-org', 'AWS_ID': PARTICIPANT,
            'UPDATE_TAG': PARTICIPANT_TAG, 'LIMIT_SIZE': 100,
        },
    )

    assert _subnet_claims(neo4j_session) == {OWNER}
    subnet = neo4j_session.run(
        """
        MATCH (s:EC2Subnet{subnetid: 'subnet-sv-1'})-[:MEMBER_OF_AWS_VPC]->(:AWSVpc{id: 'vpc-sv-3'})
        RETURN s.is_default AS is_default, s.lastupdated AS tag
        """,
    ).single()
    assert (subnet['is_default'], subnet['tag']) == (True, OWNER_TAG)
