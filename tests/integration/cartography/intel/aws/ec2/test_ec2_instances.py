from unittest.mock import patch

import cartography.intel.aws.ec2.instances
import cartography.intel.aws.ec2.route_tables
import cartography.intel.aws.ec2.subnets
import cartography.intel.aws.iam
import tests.data.aws.ec2.instances
import tests.data.aws.ec2.route_tables
import tests.data.aws.ec2.subnets
import tests.data.aws.iam
from cartography.util import run_analysis_job
from tests.data.aws.ec2.instances import DESCRIBE_INSTANCES
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = '123'


@patch.object(cartography.intel.aws.ec2.instances, 'get_ec2_instances', return_value=DESCRIBE_INSTANCES['Reservations'])
def test_sync_ec2_instances(mock_get_instances, neo4j_session):
    """
    Ensure that instances actually get loaded and have their key fields
    """
    data = tests.data.aws.ec2.instances.DESCRIBE_INSTANCES['Reservations']
    cartography.intel.aws.ec2.instances.load_ec2_instances(
        neo4j_session, data, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    # Assert EC2 instances exist
    assert check_nodes(neo4j_session, 'EC2Instance', ['id', 'instanceid']) == {
        ("i-01", "i-01"),
        ("i-02", "i-02"),
        ("i-03", "i-03"),
        ("i-04", "i-04"),
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

    # Assert network interface to instances
    assert check_rels(
        neo4j_session,
        'NetworkInterface',
        'id',
        'EC2Instance',
        'id',
        'NETWORK_INTERFACE',
        rel_direction_right=False,
    ) == {
        ('eni-de', 'i-01'),
        ('eni-87', 'i-02'),
        ('eni-75', 'i-03'),
        ('eni-76', 'i-04'),
    }

    # Assert network interface to subnet
    assert check_rels(
        neo4j_session,
        'NetworkInterface',
        'id',
        'EC2Subnet',
        'id',
        'PART_OF_SUBNET',
        rel_direction_right=True,
    ) == {
        ('eni-75', 'SOME_SUBNET_1'),
        ('eni-76', 'SOME_SUBNET_1'),
        ('eni-87', 'SOME_SUBNET_1'),
    }

    # Assert network interface to security group
    assert check_rels(
        neo4j_session,
        'NetworkInterface',
        'id',
        'EC2SecurityGroup',
        'id',
        'MEMBER_OF_EC2_SECURITY_GROUP',
        rel_direction_right=True,
    ) == {
        ('eni-75', 'SOME_GROUP_ID_2'),
        ('eni-75', 'THIS_IS_A_SG_ID'),
        ('eni-76', 'SOME_GROUP_ID_2'),
        ('eni-76', 'THIS_IS_A_SG_ID'),
        ('eni-87', 'SOME_GROUP_ID_2'),
        ('eni-87', 'SOME_GROUP_ID_3'),
        ('eni-de', 'SOME_GROUP_ID_2'),
        ('eni-de', 'sg-GROUP-ID'),
    }

    # Assert network interface to AWS account
    assert check_rels(
        neo4j_session,
        'NetworkInterface',
        'id',
        'AWSAccount',
        'id',
        'RESOURCE',
        rel_direction_right=False,
    ) == {
        ('eni-75', '000000000000'),
        ('eni-76', '000000000000'),
        ('eni-87', '000000000000'),
        ('eni-de', '000000000000'),
    }

    # Assert EC2 Key Pair to AWS account
    assert check_rels(
        neo4j_session,
        'EC2KeyPair',
        'id',
        'AWSAccount',
        'id',
        'RESOURCE',
        rel_direction_right=False,
    ) == {
        ('arn:aws:ec2:us-east-1:000000000000:key-pair/boot', '000000000000'),
    }

    # Assert EC2 Key Pair to EC2 instance
    assert check_rels(
        neo4j_session,
        'EC2KeyPair',
        'id',
        'EC2Instance',
        'id',
        'SSH_LOGIN_TO',
        rel_direction_right=True,
    ) == {
        ('arn:aws:ec2:us-east-1:000000000000:key-pair/boot', 'i-01'),
        ('arn:aws:ec2:us-east-1:000000000000:key-pair/boot', 'i-02'),
        ('arn:aws:ec2:us-east-1:000000000000:key-pair/boot', 'i-03'),
        ('arn:aws:ec2:us-east-1:000000000000:key-pair/boot', 'i-04'),
    }

    # Assert EC2 Security Group to EC2 Instance
    assert check_rels(
        neo4j_session,
        'EC2SecurityGroup',
        'id',
        'EC2Instance',
        'id',
        'MEMBER_OF_EC2_SECURITY_GROUP',
        rel_direction_right=False,
    ) == {
        ('sg-GROUP-ID', 'i-01'),
        ('SOME_GROUP_ID_2', 'i-01'),
        ('SOME_GROUP_ID_2', 'i-02'),
        ('SOME_GROUP_ID_2', 'i-03'),
        ('SOME_GROUP_ID_2', 'i-04'),
        ('SOME_GROUP_ID_3', 'i-02'),
        ('THIS_IS_A_SG_ID', 'i-03'),
        ('THIS_IS_A_SG_ID', 'i-04'),
    }

    # Assert EC2 Security Group to AWS account
    assert check_rels(
        neo4j_session,
        'EC2SecurityGroup',
        'id',
        'AWSAccount',
        'id',
        'RESOURCE',
        rel_direction_right=False,
    ) == {
        ('SOME_GROUP_ID_2', '000000000000'),
        ('SOME_GROUP_ID_3', '000000000000'),
        ('THIS_IS_A_SG_ID', '000000000000'),
        ('sg-GROUP-ID', '000000000000'),
    }

    # Assert EC2 Subnet to EC2 Instance
    assert check_rels(
        neo4j_session,
        'EC2Subnet',
        'id',
        'EC2Instance',
        'id',
        'PART_OF_SUBNET',
        rel_direction_right=False,
    ) == {
        ('SOME_SUBNET_1', 'i-02'),
        ('SOME_SUBNET_1', 'i-03'),
        ('SOME_SUBNET_1', 'i-04'),
    }

    # Assert EC2 Subnet to AWS account
    assert check_rels(
        neo4j_session,
        'EC2Subnet',
        'id',
        'AWSAccount',
        'id',
        'RESOURCE',
        rel_direction_right=False,
    ) == {
        ('SOME_SUBNET_1', '000000000000'),
    }

    # Assert EBS Volume to EC2 Instance
    assert check_rels(
        neo4j_session,
        'EBSVolume',
        'id',
        'EC2Instance',
        'id',
        'ATTACHED_TO',
        rel_direction_right=True,
    ) == {
        ('vol-0df', 'i-01'),
        ('vol-03', 'i-02'),
        ('vol-09', 'i-03'),
        ('vol-04', 'i-04'),
    }

    # Assert EBS Volume to AWS account
    assert check_rels(
        neo4j_session,
        'EBSVolume',
        'id',
        'AWSAccount',
        'id',
        'RESOURCE',
        rel_direction_right=False,
    ) == {
        ('vol-03', '000000000000'),
        ('vol-04', '000000000000'),
        ('vol-09', '000000000000'),
        ('vol-0df', '000000000000'),
    }


@patch.object(cartography.intel.aws.ec2.instances, 'get_ec2_instances', return_value=DESCRIBE_INSTANCES['Reservations'])
def test_ec2_iaminstanceprofiles(mock_get_instances, neo4j_session):
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

    # Act
    run_analysis_job(
        'aws_ec2_iaminstanceprofile.json',
        neo4j_session,
        common_job_parameters,
    )

    # Assert
    assert check_rels(
        neo4j_session,
        'EC2Instance',
        'id',
        'AWSRole',
        'arn',
        'STS_ASSUMEROLE_ALLOW',
        rel_direction_right=True,
    ) == {
        ('i-02', 'arn:aws:iam::000000000000:role/SERVICE_NAME_2'),
        ('i-03', 'arn:aws:iam::000000000000:role/ANOTHER_SERVICE_NAME'),
        ('i-04', 'arn:aws:iam::000000000000:role/ANOTHER_SERVICE_NAME'),
    }


def test_ec2_asset_exposure(neo4j_session):
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

    neo4j_session.run(
        """
        MERGE (:AWSVpc{id : 'vpc-025873e026b9e8ee6'})
        """,
    )
    data_instances = tests.data.aws.ec2.instances.DESCRIBE_INSTANCES['Reservations']
    cartography.intel.aws.ec2.instances.load_ec2_instance_data(
        neo4j_session, data_instances, TEST_ACCOUNT_ID, TEST_UPDATE_TAG,
    )

    data = tests.data.aws.ec2.route_tables.DESCRIBE_ROUTE_TABLES
    cartography.intel.aws.ec2.route_tables.load_route_tables(
        neo4j_session,
        data,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
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
        "PUBLIC_PORTS": ['20', '21', '22', '3306', '3389', '4333'],
    }

    run_analysis_job(
        'implicit_relationship_creation.json',
        neo4j_session,
        common_job_parameters,
    )

    run_analysis_job(
        'aws_ec2_subnet_asset_exposure.json',
        neo4j_session,
        common_job_parameters,
    )

    run_analysis_job(
        'aws_ec2_security_group_asset_exposure.json',
        neo4j_session,
        common_job_parameters,
    )

    run_analysis_job(
        'aws_ec2_instance_asset_exposure.json',
        neo4j_session,
        common_job_parameters,
    )

    expected_nodes = {
        ('i-03', 'public_ip, public_subnet_ipv4'),
        ('i-04', 'public_ip, public_subnet_ipv6'),
        ('i-02', 'public_ip, public_subnet_ipv4'),
        ('i-01', 'public_ip, public_subnet_ipv6'),
    }

    nodes = neo4j_session.run(
        """
        MATCH (instance:EC2Instance{exposed_internet: true}) return instance.id, instance.exposed_internet_type
        """,
    )

    actual_nodes = {
        (
            n['instance.id'],
            ", ".join(n['instance.exposed_internet_type']),
        )
        for n in nodes
    }

    assert actual_nodes == expected_nodes


EXPOSURE_ACCOUNT_ID = '111111111111'
EXPOSURE_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG + 1,
    'AWS_ID': EXPOSURE_ACCOUNT_ID,
    'ORGANIZATION_ID': 'o-ec2-exposure',
    'WORKSPACE_ID': 'ws-ec2-exposure',
    'LIMIT_SIZE': 100,
}


def test_ec2_instance_direct_exposure_requires_a_public_ip(neo4j_session):
    create_test_org_account(
        neo4j_session, EXPOSURE_JOB_PARAMETERS['WORKSPACE_ID'], EXPOSURE_JOB_PARAMETERS['ORGANIZATION_ID'],
        EXPOSURE_ACCOUNT_ID,
    )
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (open4:EC2SecurityGroup{id: 'sg-exp-open4'})
        MERGE (:IpRange{id: '0.0.0.0/0', range: '0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->
              (:IpPermissionInbound{ruleid: 'sg-exp-open4/tcp/22'})-[:MEMBER_OF_EC2_SECURITY_GROUP]->(open4)
        MERGE (open6:EC2SecurityGroup{id: 'sg-exp-open6'})
        MERGE (:Ipv6Range{id: '::/0', range: '::/0'})-[:MEMBER_OF_IP_RULE]->
              (:IpPermissionInbound{ruleid: 'sg-exp-open6/tcp/22'})-[:MEMBER_OF_EC2_SECURITY_GROUP]->(open6)
        MERGE (:EC2SecurityGroup{id: 'sg-exp-closed'})
        WITH aa
        UNWIND $instances AS i
        MERGE (aa)-[:RESOURCE]->(n:EC2Instance{id: i.id})
        SET n.state = 'running', n.publicipaddress = i.public_ip, n.exposed_internet = i.stale
        WITH n, i
        MATCH (sg:EC2SecurityGroup{id: i.sg})
        MERGE (n)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        FOREACH (_ IN CASE WHEN i.eni_ip IS NULL THEN [] ELSE [1] END |
            MERGE (n)-[:NETWORK_INTERFACE]->(:NetworkInterface{id: i.id + '-eni', public_ip: i.eni_ip}))
        FOREACH (_ IN CASE WHEN i.secondary_ip IS NULL THEN [] ELSE [1] END |
            MERGE (n)-[:NETWORK_INTERFACE]->(eni:NetworkInterface{id: i.id + '-eni2'})
            MERGE (eni)-[:PRIVATE_IP_ADDRESS]->(:EC2PrivateIp{id: i.id + '-ip2', public_ip: i.secondary_ip}))
        """,
        account_id=EXPOSURE_ACCOUNT_ID, instances=[
            # Open SG but no public address: nothing on the internet can route to it.
            {'id': 'exp-no-ip', 'sg': 'sg-exp-open4', 'stale': True},
            {'id': 'exp-public-ip', 'sg': 'sg-exp-open4', 'public_ip': '54.0.0.1'},
            # Public IP only on an attached ENI or on a secondary private IP (Elastic IP).
            {'id': 'exp-eni-ip', 'sg': 'sg-exp-open4', 'eni_ip': '54.0.0.2'},
            {'id': 'exp-secondary-ip', 'sg': 'sg-exp-open4', 'secondary_ip': '54.0.0.3'},
            {'id': 'exp-public-ip-closed-sg', 'sg': 'sg-exp-closed', 'public_ip': '54.0.0.4'},
            # Behind an internet-facing load balancer whose SG is open: public through the LB.
            {'id': 'exp-behind-lb', 'sg': 'sg-exp-closed'},
            # IPv6 addresses on ENIs are not ingested, so the ::/0 path is unchanged.
            {'id': 'exp-ipv6-open', 'sg': 'sg-exp-open6'},
        ],
    )
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id}), (n:EC2Instance{id: 'exp-behind-lb'})
        MATCH (sg:EC2SecurityGroup{id: 'sg-exp-open4'})
        MERGE (aa)-[:RESOURCE]->(lb:LoadBalancerV2{id: 'exp-lb', scheme: 'internet-facing'})-[:EXPOSE]->(n)
        MERGE (lb)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        """,
        account_id=EXPOSURE_ACCOUNT_ID,
    )

    run_analysis_job('aws_ec2_instance_asset_exposure.json', neo4j_session, EXPOSURE_JOB_PARAMETERS)

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(n:EC2Instance{exposed_internet: true})
        WHERE n.id STARTS WITH 'exp-'
        RETURN n.id AS id, n.exposed_internet_type AS types
        """,
        account_id=EXPOSURE_ACCOUNT_ID,
    )
    assert {n['id']: sorted(n['types']) for n in nodes} == {
        'exp-public-ip': ['direct_inbound_ipv4'],
        'exp-eni-ip': ['direct_inbound_ipv4'],
        'exp-secondary-ip': ['direct_inbound_ipv4'],
        'exp-behind-lb': ['unrestricted_inbound_traffic_ipv4'],
        'exp-ipv6-open': ['direct_inbound_ipv6'],
    }


NLB_ACCOUNT_ID = '111111112222'
NLB_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG + 1,
    'AWS_ID': NLB_ACCOUNT_ID,
    'ORGANIZATION_ID': 'o-ec2-nlb',
    'WORKSPACE_ID': 'ws-ec2-nlb',
    'LIMIT_SIZE': 100,
}


def test_ec2_instance_exposed_through_internet_facing_nlb_without_security_group(neo4j_session):
    # NLBs created before August 2023 have no security group: the LB forwards every listener port from
    # anywhere, so the SG-based LB statements never match the instances behind it.
    create_test_org_account(
        neo4j_session, NLB_JOB_PARAMETERS['WORKSPACE_ID'], NLB_JOB_PARAMETERS['ORGANIZATION_ID'], NLB_ACCOUNT_ID,
    )
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (:EC2SecurityGroup{id: 'sg-nlb-closed'})
        WITH aa
        UNWIND $lbs AS l
        MERGE (aa)-[:RESOURCE]->(lb:LoadBalancerV2{id: l.id})
        SET lb.scheme = l.scheme, lb.type = l.type
        MERGE (aa)-[:RESOURCE]->(n:EC2Instance{id: l.instance})
        // No public address: the LB path does not need one.
        SET n.state = l.state
        MERGE (lb)-[:EXPOSE]->(n)
        WITH lb, n, l
        MATCH (closed:EC2SecurityGroup{id: 'sg-nlb-closed'})
        MERGE (n)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(closed)
        FOREACH (_ IN CASE WHEN l.sg THEN [1] ELSE [] END | MERGE (lb)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(closed))
        """,
        account_id=NLB_ACCOUNT_ID, lbs=[
            {
                'id': 'nlb-public', 'scheme': 'internet-facing', 'type': 'network', 'instance': 'nlb-i-public',
                'state': 'running',
            },
            {
                'id': 'nlb-internal', 'scheme': 'internal', 'type': 'network', 'instance': 'nlb-i-internal',
                'state': 'running',
            },
            {
                'id': 'nlb-public-stopped', 'scheme': 'internet-facing', 'type': 'network',
                'instance': 'nlb-i-stopped', 'state': 'stopped',
            },
            # An NLB with a security group goes through the SG statements: this one allows nothing.
            {
                'id': 'nlb-public-closed-sg', 'scheme': 'internet-facing', 'type': 'network',
                'instance': 'nlb-i-closed-sg', 'state': 'running', 'sg': True,
            },
            # An ALB always has a security group; one that looks SG-less is missing data, not open.
            {
                'id': 'alb-public-no-sg', 'scheme': 'internet-facing', 'type': 'application',
                'instance': 'nlb-i-alb', 'state': 'running',
            },
        ],
    )

    run_analysis_job('aws_ec2_instance_asset_exposure.json', neo4j_session, NLB_JOB_PARAMETERS)

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(n:EC2Instance{exposed_internet: true})
        RETURN n.id AS id, n.exposed_internet_type AS types
        """,
        account_id=NLB_ACCOUNT_ID,
    )
    assert {n['id']: sorted(n['types']) for n in nodes} == {'nlb-i-public': ['internet_facing_nlb']}
