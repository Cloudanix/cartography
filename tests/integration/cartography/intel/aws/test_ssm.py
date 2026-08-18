from unittest.mock import MagicMock
from unittest.mock import patch

import cartography.intel.aws.ec2.instances
import cartography.intel.aws.ssm
import tests.data.aws.ec2.instances
import tests.data.aws.ssm
from cartography.intel.aws.ec2.instances import sync_ec2_instances
from tests.data.aws.ec2.instances import DESCRIBE_INSTANCES
from tests.integration.cartography.intel.aws.common import create_test_account

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789


def _ensure_load_instances(neo4j_session):
    data = tests.data.aws.ec2.instances.DESCRIBE_INSTANCES['Reservations']
    cartography.intel.aws.ec2.instances.load_ec2_instances(
        neo4j_session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
    )


def _ensure_ec2_instances_with_region(neo4j_session):
    """Create EC2Instance nodes linked to the test account, with region set for SSM status matching."""
    neo4j_session.run(
        """
        MATCH (aws:AWSAccount{id: $aws_account_id})
        UNWIND $instance_ids AS instance_id
        MERGE (i:EC2Instance{id: instance_id})
        ON CREATE SET i.firstseen = timestamp()
        SET i.instanceid = instance_id,
            i.region = $region,
            i.lastupdated = $aws_update_tag
        MERGE (aws)-[:RESOURCE]->(i)
        """,
        aws_account_id=TEST_ACCOUNT_ID,
        instance_ids=['i-01', 'i-02', 'i-03', 'i-04'],
        region=TEST_REGION,
        aws_update_tag=TEST_UPDATE_TAG,
    )


@patch.object(cartography.intel.aws.ec2.instances, 'get_ec2_instances', return_value=DESCRIBE_INSTANCES['Reservations'])
def test_load_instance_information(mock_get_instances, neo4j_session):
    # Arrange
    # load account and instances, to be able to test relationships
    create_test_account(neo4j_session, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
    _ensure_load_instances(neo4j_session)

    # Act
    data_list = cartography.intel.aws.ssm.transform_instance_information(tests.data.aws.ssm.INSTANCE_INFORMATION, TEST_REGION, TEST_ACCOUNT_ID)
    cartography.intel.aws.ssm.load_instance_information(
        neo4j_session,
        data_list,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_nodes = {
        ("i-01", 1647233782, 1647233908, 1647232108),
        ("i-02", 1647233782, 1647233908, 1647232108),
    }

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: "000000000000"})-[:RESOURCE]->(n:SSMInstanceInformation)
        RETURN n.id,
               n.last_ping_date_time,
               n.last_association_execution_date,
               n.last_successful_association_execution_date
        """,
    )
    actual_nodes = {
        (
            n["n.id"],
            n["n.last_ping_date_time"],
            n["n.last_association_execution_date"],
            n["n.last_successful_association_execution_date"],
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes

    nodes = neo4j_session.run(
        """
        MATCH (:EC2Instance{id: "i-01"})-[:HAS_INFORMATION]->(n:SSMInstanceInformation)
        RETURN n.id
        """,
    )
    actual_nodes = {n["n.id"] for n in nodes}
    assert actual_nodes == {"i-01"}

    nodes = neo4j_session.run(
        """
        MATCH (:EC2Instance{id: "i-02"})-[:HAS_INFORMATION]->(n:SSMInstanceInformation)
        RETURN n.id
        """,
    )
    actual_nodes = {n["n.id"] for n in nodes}
    assert actual_nodes == {"i-02"}


@patch.object(cartography.intel.aws.ec2.instances, 'get_ec2_instances', return_value=DESCRIBE_INSTANCES['Reservations'])
def test_load_instance_patches(mock_get_instances, neo4j_session):
    # Arrange: load account and instances, to be able to test relationships
    create_test_account(neo4j_session, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
    _ensure_load_instances(neo4j_session)

    # Act
    data_list = cartography.intel.aws.ssm.transform_instance_patches(tests.data.aws.ssm.INSTANCE_PATCHES, TEST_REGION, TEST_ACCOUNT_ID)
    cartography.intel.aws.ssm.load_instance_patches(
        neo4j_session,
        data_list,
        TEST_REGION,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    # Assert
    expected_nodes = {
        ("i-01-test.x86_64:0:4.2.46-34.amzn2", 1636404678, ("CVE-2022-0000", "CVE-2022-0001")),
        ("i-02-test.x86_64:0:4.2.46-34.amzn2", 1636404678, ("CVE-2022-0000", "CVE-2022-0001")),
    }
    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: "000000000000"})-[:RESOURCE]->(n:SSMInstancePatch)
        RETURN n.id,
               n.installed_time,
               n.cve_ids
        """,
    )
    actual_nodes = {
        (
            n["n.id"],
            n["n.installed_time"],
            tuple(n["n.cve_ids"]),
        )
        for n in nodes
    }
    assert actual_nodes == expected_nodes

    # Assert
    nodes = neo4j_session.run(
        """
        MATCH (:EC2Instance{id: "i-01"})-[:HAS_PATCH]->(n:SSMInstancePatch)
        RETURN n.id
        """,
    )
    actual_nodes = {n["n.id"] for n in nodes}
    assert actual_nodes == {"i-01-test.x86_64:0:4.2.46-34.amzn2"}

    # Assert
    nodes = neo4j_session.run(
        """
        MATCH (:EC2Instance{id: "i-02"})-[:HAS_PATCH]->(n:SSMInstancePatch)
        RETURN n.id
        """,
    )
    actual_nodes = {n["n.id"] for n in nodes}
    assert actual_nodes == {"i-02-test.x86_64:0:4.2.46-34.amzn2"}


def test_load_ec2_ssm_status(neo4j_session):
    """EC2 instances returned by DescribeInstanceInformation get ssmenabled=true and agent version;
    queried instances missing from the response get ssmenabled=false."""
    create_test_account(neo4j_session, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
    _ensure_ec2_instances_with_region(neo4j_session)

    instance_ids = ['i-01', 'i-02', 'i-03', 'i-04']
    status_list = cartography.intel.aws.ssm.transform_ec2_ssm_status(
        instance_ids,
        tests.data.aws.ssm.INSTANCE_INFORMATION,
    )
    cartography.intel.aws.ssm.load_ec2_ssm_status(
        neo4j_session,
        status_list,
        TEST_REGION,
        TEST_ACCOUNT_ID,
    )

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(i:EC2Instance)
        RETURN i.id AS id, i.ssmenabled AS ssmenabled, i.ssmagentversion AS ssmagentversion
        """,
        account_id=TEST_ACCOUNT_ID,
    )
    actual_nodes = {
        (n["id"], n["ssmenabled"], n["ssmagentversion"])
        for n in nodes
    }
    assert actual_nodes == {
        ("i-01", True, "3.1.1004.1"),
        ("i-02", True, "3.1.1004.0"),
        ("i-03", False, None),
        ("i-04", False, None),
    }
