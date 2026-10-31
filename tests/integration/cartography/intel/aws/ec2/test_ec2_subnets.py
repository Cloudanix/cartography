import cartography.intel.aws.ec2.subnets
import tests.data.aws.ec2.subnets
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters


TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'eu-north-1'
TEST_UPDATE_TAG = 123456789


def test_load_subnets(neo4j_session):
    data = tests.data.aws.ec2.subnets.DESCRIBE_SUBNETS
    cartography.intel.aws.ec2.subnets.load_subnets(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        "arn:aws:ec2:eu-north-1:000000000000:subnet/subnet-0773409557644dca4",
        "arn:aws:ec2:eu-north-1:000000000000:subnet/subnet-020b2f3928f190ce8",
        "arn:aws:ec2:eu-north-1:000000000000:subnet/subnet-0fa9c8fa7cb241479",
    }

    nodes = neo4j_session.run(
        """
        MATCH (s:EC2Subnet) RETURN s.subnet_arn;
        """,
    )
    actual_nodes = {n['s.subnet_arn'] for n in nodes}

    assert actual_nodes == expected_nodes


def test_load_subnet_relationships(neo4j_session):
    # Create Test AWSAccount
    neo4j_session.run(
        """
        MERGE (aws:AWSAccount{id: $aws_account_id})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        aws_account_id=TEST_ACCOUNT_ID,
        aws_update_tag=TEST_UPDATE_TAG,
    )

    data = tests.data.aws.ec2.subnets.DESCRIBE_SUBNETS
    cartography.intel.aws.ec2.subnets.load_subnets(
        neo4j_session,
        data,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        ('000000000000', 'arn:aws:ec2:eu-north-1:000000000000:subnet/subnet-0fa9c8fa7cb241479'),
        ('000000000000', 'arn:aws:ec2:eu-north-1:000000000000:subnet/subnet-020b2f3928f190ce8'),
        ('000000000000', 'arn:aws:ec2:eu-north-1:000000000000:subnet/subnet-0773409557644dca4'),
    }

    # Fetch relationships
    result = neo4j_session.run(
        """
        MATCH (n1:AWSAccount)-[:RESOURCE]->(n2:EC2Subnet) RETURN n1.id, n2.subnet_arn;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.subnet_arn']) for r in result
    }

    assert actual == expected_nodes


def test_subnet_exposure_marks_map_public_ip_on_launch_through_the_organization(neo4j_session):
    account_id = '111111111111'
    create_test_org_account(neo4j_session, 'ws-subnet', 'o-subnet', account_id)
    cartography.intel.aws.ec2.subnets.load_subnets(
        neo4j_session, [
            {'SubnetId': 'subnet-auto-public-ip', 'CidrBlock': '10.0.1.0/24', 'MapPublicIpOnLaunch': True},
            {'SubnetId': 'subnet-no-public-ip', 'CidrBlock': '10.0.2.0/24', 'MapPublicIpOnLaunch': False},
        ], account_id, TEST_UPDATE_TAG,
    )

    run_analysis_job(
        'aws_ec2_subnet_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-subnet', 'o-subnet', account_id, TEST_UPDATE_TAG + 1),
    )

    result = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(s:EC2Subnet{exposed_internet: true})
        RETURN s.subnetid AS id, s.exposed_internet_type AS types
        """,
        account_id=account_id,
    )
    assert {r['id']: r['types'] for r in result} == {'subnet-auto-public-ip': ['map_public_ip_on_launch']}
