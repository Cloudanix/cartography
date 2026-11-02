import cartography.intel.aws.ec2.load_balancers
import cartography.intel.aws.ec2.security_groups
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
WORKSPACE_ID = 'ws-clb'
ORG_ID = 'o-clb'
ACCOUNT_ID = '777777777799'
VPC_ID = 'vpc-clb'


def _group(neo4j_session, group_id, name, port, cidr=None, prefix_list=None):
    # Loaded through the real rule loader so the test reads what a sync writes.
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (aa)-[:RESOURCE]->(sg:EC2SecurityGroup{id: $id}) SET sg.groupid = $id, sg.name = $name
        MERGE (aa)-[:RESOURCE]->(vpc:AWSVpc{id: $vpc_id})
        MERGE (vpc)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        """,
        account_id=ACCOUNT_ID, id=group_id, name=name, vpc_id=VPC_ID,
    )
    cartography.intel.aws.ec2.security_groups.load_ec2_security_group_rules(
        neo4j_session,
        [{
            'GroupId': group_id,
            'IpPermissions': [{
                'IpProtocol': 'tcp', 'FromPort': port, 'ToPort': port,
                'IpRanges': [{'CidrIp': cidr}] if cidr else [], 'Ipv6Ranges': [],
                'PrefixListIds': [{'PrefixListId': prefix_list}] if prefix_list else [],
            }],
            'IpPermissionsEgress': [],
        }],
        TEST_UPDATE_TAG,
    )


def _classic(name, group_id):
    return {
        'DNSName': f'{name}.us-east-1.elb.amazonaws.com',
        'LoadBalancerName': name,
        'CreatedTime': '2019-10-27 00:35:00',
        'Scheme': 'internet-facing',
        'region': 'us-east-1',
        'VPCId': VPC_ID,
        'Subnets': [],
        'SecurityGroups': [group_id],
        # The VPC's "default" group: a name reference, not necessarily what guards the listener.
        'SourceSecurityGroup': {'OwnerAlias': ACCOUNT_ID, 'GroupName': 'default'},
        'Instances': [],
        'ListenerDescriptions': [{
            'Listener': {'LoadBalancerPort': 443, 'Protocol': 'HTTPS', 'InstancePort': 443, 'InstanceProtocol': 'HTTP'},
        }],
    }


def _exposure(neo4j_session, name):
    row = neo4j_session.run(
        "MATCH (elb:LoadBalancer{name: $name}) OPTIONAL MATCH (elb)-[:ELB_LISTENER]->(l:ELBListener) "
        "RETURN elb.exposed_internet AS exposed, elb.exposed_internet_type AS types, "
        "l.exposed_internet AS listener_exposed, l.exposed_internet_type AS listener_types",
        name=name,
    ).single()
    return (
        row['exposed'], sorted(row['types'] or []), row['listener_exposed'], sorted(row['listener_types'] or []),
    )


def test_classic_elb_exposure_follows_its_attached_security_groups(neo4j_session):
    create_test_org_account(neo4j_session, WORKSPACE_ID, ORG_ID, ACCOUNT_ID)
    # The VPC default group is open to the world, but none of the load balancers below uses it.
    _group(neo4j_session, 'sg-clb-default', 'default', 443, cidr='0.0.0.0/0')
    _group(neo4j_session, 'sg-clb-corp', 'corp', 443, cidr='10.0.0.0/8')
    _group(neo4j_session, 'sg-clb-open', 'open', 443, cidr='0.0.0.0/0')
    _group(neo4j_session, 'sg-clb-cdn', 'cdn', 443, prefix_list='pl-3b927c52')
    cartography.intel.aws.ec2.load_balancers.load_load_balancers(
        neo4j_session,
        [_classic('clb-corp', 'sg-clb-corp'), _classic('clb-open', 'sg-clb-open'), _classic('clb-cdn', 'sg-clb-cdn')],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    run_analysis_job(
        'aws_ec2_elb_asset_exposure.json', neo4j_session,
        exposure_job_parameters(WORKSPACE_ID, ORG_ID, ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    # Attached group admits 10.0.0.0/8 only: not exposed, whatever the source group name points at.
    assert _exposure(neo4j_session, 'clb-corp') == (None, [], None, [])
    assert _exposure(neo4j_session, 'clb-open') == (
        True, ['unrestricted_inbound_traffic_ipv4'], True, ['loadbalancer_unrestricted_inbound_traffic_ipv4'],
    )
    assert _exposure(neo4j_session, 'clb-cdn') == (
        True, ['prefix_list_inbound'], True, ['loadbalancer_prefix_list_inbound'],
    )
