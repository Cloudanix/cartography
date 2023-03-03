import cartography.intel.aws.ec2.instances
import cartography.intel.aws.ec2.route_tables
import cartography.intel.aws.ec2.subnets
import cartography.intel.aws.iam
import tests.data.aws.ec2.instances
import tests.data.aws.ec2.route_tables
import tests.data.aws.ec2.subnets
import tests.data.aws.iam
from cartography.util import run_analysis_job

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = '123'


def test_load_ec2_instances(neo4j_session, *args):
    """
    Ensure that instances actually get loaded and have their key fields
    """
    data = tests.data.aws.ec2.instances.DESCRIBE_INSTANCES['Reservations']
    cartography.intel.aws.ec2.instances.load_ec2_instances(
        neo4j_session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            "i-01",
            "i-01",
        ),
        (
            "i-02",
            "i-02",
        ),
        (
            "i-03",
            "i-03",
        ),
        (
            "i-04",
            "i-04",
        ),
    }

    nodes = neo4j_session.run(
        """
        MATCH (i:EC2Instance) return i.id, i.instanceid
        """,
    )
    actual_nodes = {
        (
            n['i.id'],
            n['i.instanceid'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes


def test_ec2_reservations_to_instances(neo4j_session, *args):
    """
    Ensure that instances are connected to their expected reservations
    """
    data = tests.data.aws.ec2.instances.DESCRIBE_INSTANCES['Reservations']
    cartography.intel.aws.ec2.instances.load_ec2_instances(
        neo4j_session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    expected_nodes = {
        (
            "r-01",
            "i-01",
        ),
        (
            "r-02",
            "i-02",
        ),
        (
            "r-03",
            "i-03",
        ),
        (
            "r-03",
            "i-04",
        ),
    }

    nodes = neo4j_session.run(
        """
    MATCH (r:EC2Reservation)<-[:MEMBER_OF_EC2_RESERVATION]-(i:EC2Instance) RETURN r.reservationid, i.id
    """,
    )
    actual_nodes = {
        (
            n['r.reservationid'],
            n['i.id'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes


def test_ec2_iaminstanceprofiles(neo4j_session):
    """
    Ensure that EC2Instances are attached to the IAM Roles that they can assume due to their IAM instance profiles
    """
    neo4j_session.run(
        """
        MERGE (aws:AWSAccount{id: $aws_account_id})<-[:OWNER]-(:CloudanixWorkspace{id: $workspace_id})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        aws_account_id=TEST_ACCOUNT_ID,
        aws_update_tag=TEST_UPDATE_TAG,
        workspace_id=TEST_WORKSPACE_ID,
    )

    data_instances = tests.data.aws.ec2.instances.DESCRIBE_INSTANCES['Reservations']
    data_iam = tests.data.aws.iam.INSTACE['Roles']

    cartography.intel.aws.ec2.instances.load_ec2_instances(
        neo4j_session, data_instances, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    cartography.intel.aws.iam.load_roles(
        neo4j_session, data_iam, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    common_job_parameters = {
        "UPDATE_TAG": TEST_UPDATE_TAG,
        "WORKSPACE_ID": TEST_WORKSPACE_ID,
    }

    run_analysis_job(
        'aws_ec2_iaminstanceprofile.json',
        neo4j_session,
        common_job_parameters,
    )

    expected_nodes = {
        ('arn:aws:iam::000000000000:role/SERVICE_NAME_2', 'i-02'),
        ('arn:aws:iam::000000000000:role/ANOTHER_SERVICE_NAME', 'i-03'),
        ('arn:aws:iam::000000000000:role/ANOTHER_SERVICE_NAME', 'i-04'),
    }

    nodes = neo4j_session.run(
        """
        MATCH (i:EC2Instance)-[:STS_ASSUMEROLE_ALLOW]->(r:AWSRole) return r.arn, i.id
        """,
    )
    actual_nodes = {
        (
            n['r.arn'],
            n['i.id'],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes


def test_ec2_asset_exposure(neo4j_session):
    neo4j_session.run(
        """
        MERGE (aws:AWSAccount{id: $aws_account_id})<-[:OWNER]-(:CloudanixWorkspace{id: $workspace_id})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        aws_account_id=TEST_ACCOUNT_ID,
        aws_update_tag=TEST_UPDATE_TAG,
        workspace_id=TEST_WORKSPACE_ID
    )

    data = tests.data.aws.ec2.route_tables.DESCRIBE_ROUTE_TABLES
    cartography.intel.aws.ec2.route_tables.load_route_tables(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG
    )

    data_instances = tests.data.aws.ec2.instances.DESCRIBE_INSTANCES['Reservations']
    cartography.intel.aws.ec2.instances.load_ec2_instances(
        neo4j_session, data_instances, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    data = tests.data.aws.ec2.subnets.DESCRIBE_SUBNETS
    cartography.intel.aws.ec2.subnets.load_subnets(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )
    common_job_parameters = {
        "UPDATE_TAG": TEST_UPDATE_TAG + 1,
        "WORKSPACE_ID": TEST_WORKSPACE_ID,
        "AWS_ID": TEST_ACCOUNT_ID,
        "public_ports": ['20', '21', '22', '3306', '3389', '4333'],
    }

    run_analysis_job(
        'aws_ec2_asset_exposure.json',
        neo4j_session,
        common_job_parameters,
    )

    expected_nodes = {
        ('i-01',
         'public_subnet_implicit, vpc_none'),
        ('i-02',
         'public_subnet_explicit, vpc_none'),
        ('i-03',
         'public_subnet_explicit, vpc_none'),
        ('i-04',
         'public_subnet_explicit, vpc_none'),
    }

    nodes = neo4j_session.run(
        """
        MATCH (instance:EC2Instance{exposed_internet: true}) return instance.id, instance.exposed_internet_type
        """,
    )

    actual_nodes = {
        (
            n['instance.id'],
            ", ".join(n['instance.exposed_internet_type'])
        )
        for n in nodes
    }

    assert actual_nodes == expected_nodes
