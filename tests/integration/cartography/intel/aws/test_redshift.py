import json

import cartography.intel.aws.ec2.security_groups
import cartography.intel.aws.redshift
import tests.data.aws.redshift
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_ACCOUNT_ID = '1111'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789


def test_load_redshift_cluster_data(neo4j_session):
    _ensure_local_neo4j_has_test_cluster_data(neo4j_session)

    # Test that the Redshift cluster node was created
    expected_nodes = {
        "arn:aws:redshift:us-east-1:1111:cluster:my-cluster",
    }
    nodes = neo4j_session.run(
        """
        MATCH (n:RedshiftCluster) RETURN n.id;
        """,
    )
    actual_nodes = {n['n.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def test_load_redshift_redshift_reserved_node_data(neo4j_session):
    _ensure_local_neo4j_has_test_redshift_reserved_node_data(neo4j_session)
    expected_nodes = {
        "arn:aws:redshift:us-east-1:1111:reserved-node/1ba8e2e3-bc01-4d65-b35d-a4a3e931547e",
    }
    nodes = neo4j_session.run(
        """
        MATCH (n:RedshiftReservedNode) RETURN n.id;
        """,
    )
    actual_nodes = {n['n.id'] for n in nodes}
    assert actual_nodes == expected_nodes


def test_load_redshift_cluster_and_aws_account(neo4j_session):
    # Create test AWSAccount
    neo4j_session.run(
        """
        MERGE (aws:AWSAccount{id: $aws_account_id})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        aws_account_id=TEST_ACCOUNT_ID,
        aws_update_tag=TEST_UPDATE_TAG,
    )
    _ensure_local_neo4j_has_test_cluster_data(neo4j_session)

    # Test that AWSAccount-to-RedshiftCluster relationships exist
    expected = {
        (TEST_ACCOUNT_ID, 'arn:aws:redshift:us-east-1:1111:cluster:my-cluster'),
    }
    result = neo4j_session.run(
        """
        MATCH (n1:AWSAccount)-[:RESOURCE]->(n2:RedshiftCluster) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }
    assert actual == expected


def test_load_redshift_cluster_and_security_group(neo4j_session):
    # Create test EC2 security group
    neo4j_session.run(
        """
        MERGE (aws:EC2SecurityGroup{id: $GroupId})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        GroupId='sg-028e2522c72719996',
        aws_update_tag=TEST_UPDATE_TAG,
    )
    _ensure_local_neo4j_has_test_cluster_data(neo4j_session)

    # Test that RedshiftCluster-to-EC2SecurityGroup relationships exist
    expected = {
        ('sg-028e2522c72719996', 'arn:aws:redshift:us-east-1:1111:cluster:my-cluster'),
    }
    result = neo4j_session.run(
        """
        MATCH (n1:EC2SecurityGroup)<-[:MEMBER_OF_EC2_SECURITY_GROUP]-(n2:RedshiftCluster) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }
    assert actual == expected


def test_load_redshift_cluster_and_iam_role(neo4j_session):
    # Create test IAM role
    neo4j_session.run(
        """
        MERGE (aws:AWSPrincipal:AWSRole{arn: $RoleArn})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        RoleArn='arn:aws:iam::1111:role/my-test-role',
        aws_update_tag=TEST_UPDATE_TAG,
    )
    _ensure_local_neo4j_has_test_cluster_data(neo4j_session)

    # Test that RedshiftCluster-to-IAM-role relationships exist
    expected = {
        ('arn:aws:iam::1111:role/my-redshift-iam-role', 'arn:aws:redshift:us-east-1:1111:cluster:my-cluster'),
    }
    result = neo4j_session.run(
        """
        MATCH (n1:AWSPrincipal)<-[:STS_ASSUMEROLE_ALLOW]-(n2:RedshiftCluster) RETURN n1.arn, n2.id;
        """,
    )
    actual = {
        (r['n1.arn'], r['n2.id']) for r in result
    }
    assert actual == expected


def test_load_redshift_cluster_and_vpc(neo4j_session):
    # Create test VPC
    neo4j_session.run(
        """
        MERGE (aws:AWSVpc{id: $VpcId})
        ON CREATE SET aws.firstseen = timestamp()
        SET aws.lastupdated = $aws_update_tag
        """,
        VpcId='my_vpc',
        aws_update_tag=TEST_UPDATE_TAG,
    )
    _ensure_local_neo4j_has_test_cluster_data(neo4j_session)

    # Test that RedshiftCluster-to-VPC relationships exist
    expected = {
        ('my_vpc', 'arn:aws:redshift:us-east-1:1111:cluster:my-cluster'),
    }
    result = neo4j_session.run(
        """
        MATCH (n1:AWSVpc)<-[:MEMBER_OF_AWS_VPC]-(n2:RedshiftCluster) RETURN n1.id, n2.id;
        """,
    )
    actual = {
        (r['n1.id'], r['n2.id']) for r in result
    }
    assert actual == expected


def _ensure_local_neo4j_has_test_cluster_data(neo4j_session):
    """Pre-load the Neo4j instance with sample Redshift data"""
    clusters = tests.data.aws.redshift.CLUSTERS
    cartography.intel.aws.redshift.transform_redshift_cluster_data(
        clusters,
        TEST_ACCOUNT_ID,
    )
    cartography.intel.aws.redshift.load_redshift_cluster_data(
        neo4j_session,
        clusters,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )


def _ensure_local_neo4j_has_test_redshift_reserved_node_data(neo4j_session):
    nodes = tests.data.aws.redshift.NODES
    cartography.intel.aws.redshift.load_redshift_reserved_node(
        neo4j_session,
        nodes,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )


EXPOSURE_ACCOUNT_ID = '444444444444'


def _security_group(group_id, protocol, from_port, to_port, ipv4=(), ipv6=()):
    return {
        'GroupId': group_id,
        'GroupName': group_id,
        'IpPermissions': [{
            'IpProtocol': protocol,
            'FromPort': from_port,
            'ToPort': to_port,
            'IpRanges': [{'CidrIp': cidr} for cidr in ipv4],
            'Ipv6Ranges': [{'CidrIpv6': cidr} for cidr in ipv6],
        }],
        'IpPermissionsEgress': [],
    }


def _redshift_cluster(name, group_id, publicly_accessible=True, port=5439):
    cluster = {
        'arn': f'arn:aws:redshift:us-east-1:{EXPOSURE_ACCOUNT_ID}:cluster:{name}',
        'ClusterIdentifier': name,
        'PubliclyAccessible': publicly_accessible,
        'VpcSecurityGroups': [{'VpcSecurityGroupId': group_id}],
    }
    if port is not None:
        cluster['Endpoint'] = {'Address': f'{name}.example.us-east-1.redshift.amazonaws.com', 'Port': port}
    return cluster


def test_redshift_exposure_requires_open_cidr_on_the_cluster_port(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-redshift', 'o-redshift', EXPOSURE_ACCOUNT_ID)
    cartography.intel.aws.ec2.security_groups.load_ec2_security_groupinfo(
        neo4j_session, [
            _security_group('sg-rs-open', 'tcp', 5439, 5439, ipv4=['0.0.0.0/0']),
            _security_group('sg-rs-ssh', 'tcp', 22, 22, ipv4=['0.0.0.0/0']),
            _security_group('sg-rs-all', '-1', None, None, ipv4=['0.0.0.0/0']),
            _security_group('sg-rs-v6', 'tcp', 5000, 6000, ipv6=['::/0']),
            _security_group('sg-rs-office', 'tcp', 5439, 5439, ipv4=['203.0.113.0/24']),
        ], EXPOSURE_ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    cartography.intel.aws.redshift.load_redshift_cluster_data(
        neo4j_session, [
            _redshift_cluster('rs-open', 'sg-rs-open'),
            _redshift_cluster('rs-ssh-only', 'sg-rs-ssh'),
            _redshift_cluster('rs-all-traffic', 'sg-rs-all'),
            _redshift_cluster('rs-ipv6', 'sg-rs-v6'),
            _redshift_cluster('rs-office-only', 'sg-rs-office'),
            _redshift_cluster('rs-not-public', 'sg-rs-open', publicly_accessible=False),
            # No endpoint yet (e.g. still creating): the port is unknown, so any open rule counts.
            _redshift_cluster('rs-no-endpoint', 'sg-rs-ssh', port=None),
        ], EXPOSURE_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    run_analysis_job(
        'aws_redshift_cluster_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-redshift', 'o-redshift', EXPOSURE_ACCOUNT_ID, TEST_UPDATE_TAG + 1),
    )

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(n:RedshiftCluster{exposed_internet: true})
        RETURN n.cluster_identifier AS name, n.exposed_internet_type AS types, n.publicContext AS context
        """,
        account_id=EXPOSURE_ACCOUNT_ID,
    )
    exposed = {n['name']: (n['types'], json.loads(n['context'])[0]['context'][0]['securityRules']) for n in nodes}
    assert exposed == {
        'rs-open': (
            ['direct_ipv4'], [
                {'securityGroupId': 'sg-rs-open', 'port': '5439', 'protocol': 'tcp', 'ipRanges': ['0.0.0.0/0']},
            ],
        ),
        'rs-all-traffic': (
            ['direct_ipv4'], [
                {'securityGroupId': 'sg-rs-all', 'port': '0', 'protocol': '-1', 'ipRanges': ['0.0.0.0/0']},
            ],
        ),
        'rs-ipv6': (
            ['direct_ipv6'], [
                {'securityGroupId': 'sg-rs-v6', 'port': '5000', 'protocol': 'tcp', 'ipRanges': ['::/0']},
            ],
        ),
        'rs-no-endpoint': (
            ['direct_ipv4'], [
                {'securityGroupId': 'sg-rs-ssh', 'port': '22', 'protocol': 'tcp', 'ipRanges': ['0.0.0.0/0']},
            ],
        ),
    }
