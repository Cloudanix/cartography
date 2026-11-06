"""Elasticsearch, Lambda, MQ, MSK and Redshift link statements reach only the tenant's resources."""
from cartography.intel.aws import elasticsearch
from cartography.intel.aws import lambda_function
from cartography.intel.aws import mq
from cartography.intel.aws import msk
from cartography.intel.aws import redshift
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
REGION = 'us-east-1'
# OWN and SIBLING belong to one workspace, OTHER to another customer.
OWN, SIBLING, OTHER = 'sl-own', 'sl-sibling', 'sl-other'
WORKSPACE = 'sl-ws'


def _seed(neo4j_session, label, own_id, other_id):
    create_test_org_account(neo4j_session, WORKSPACE, 'sl-org', OWN)
    create_test_org_account(neo4j_session, WORKSPACE, 'sl-org', SIBLING)
    create_test_org_account(neo4j_session, 'sl-ws-other', 'sl-org-other', OTHER)
    neo4j_session.run(
        f"""
        MATCH (own:AWSAccount{{id: $own}}), (sibling:AWSAccount{{id: $sibling}}), (other:AWSAccount{{id: $other}})
        MERGE (own)-[:RESOURCE]->(:{label}{{id: $own_id}})
        MERGE (other)-[:RESOURCE]->(:{label}{{id: $other_id}})
        // a subnet and a group shared in from an account of the workspace, and another customer's
        MERGE (sibling)-[:RESOURCE]->(:EC2Subnet{{subnetid: 'subnet-sl-sibling'}})
        MERGE (sibling)-[:RESOURCE]->(:EC2SecurityGroup{{id: 'sg-sl-sibling'}})
        MERGE (other)-[:RESOURCE]->(:EC2Subnet{{subnetid: 'subnet-sl-other'}})
        MERGE (other)-[:RESOURCE]->(:EC2SecurityGroup{{id: 'sg-sl-other'}})
        """,
        own=OWN, sibling=SIBLING, other=OTHER, own_id=own_id, other_id=other_id,
    )


def _links(neo4j_session, node_id):
    return {
        (r['rel'], r['n']) for r in neo4j_session.run(
            """
            MATCH ({id: $id})-[r]-(n) WHERE NOT n:AWSAccount
            RETURN type(r) AS rel, coalesce(n.subnetid, n.id, n.arn) AS n
            """,
            id=node_id,
        )
    }


def test_es_domain_links_stay_in_the_workspace(neo4j_session):
    _seed(neo4j_session, 'ESDomain', 'es-own', 'es-other')
    vpc = {
        'VPCOptions': {
            'SubnetIds': ['subnet-sl-sibling', 'subnet-sl-other'], 'SecurityGroupIds': ['sg-sl-sibling', 'sg-sl-other'],
        },
    }
    public = {
        'Endpoint': 'e',
        'AccessPolicies': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "es:*"}]}',
    }

    for domain in ('es-own', 'es-other'):
        elasticsearch._link_es_domain_vpc(neo4j_session, domain, vpc, OWN, WORKSPACE, TAG)
        elasticsearch._process_access_policy(neo4j_session, domain, public, OWN)

    assert _links(neo4j_session, 'es-own') == {
        ('PART_OF_SUBNET', 'subnet-sl-sibling'), ('MEMBER_OF_EC2_SECURITY_GROUP', 'sg-sl-sibling'),
    }
    assert _links(neo4j_session, 'es-other') == set()
    exposed = neo4j_session.run("MATCH (es:ESDomain) WHERE es.exposed_internet RETURN es.id AS id")
    assert [r['id'] for r in exposed] == ['es-own']


def test_lambda_children_attach_only_to_the_accounts_function(neo4j_session):
    _seed(neo4j_session, 'AWSLambda', 'fn-own', 'fn-other')
    functions = ('fn-own', 'fn-other')

    lambda_function._load_lambda_function_aliases(
        neo4j_session, [{'AliasArn': f'{f}:alias', 'FunctionArn': f} for f in functions], OWN, TAG,
    )
    lambda_function._load_lambda_event_source_mappings(
        neo4j_session, [{'EventSourceArn': f'{f}:esm', 'FunctionArn': f} for f in functions], OWN, TAG,
    )
    lambda_function._load_lambda_layers(
        neo4j_session, [{'Arn': f'{f}:layer', 'FunctionArn': f} for f in functions], OWN, TAG,
    )

    assert _links(neo4j_session, 'fn-own') == {
        ('KNOWN_AS', 'fn-own:alias'), ('RESOURCE', 'fn-own:esm'), ('HAS', 'fn-own:layer'),
    }
    assert _links(neo4j_session, 'fn-other') == set()


def test_mq_brokers_link_only_inside_the_workspace(neo4j_session):
    _seed(neo4j_session, 'AWSMQBroker', 'mq-own', 'mq-other')
    brokers = [
        {'BrokerArn': b, 'SecurityGroups': ['sg-sl-new'], 'SubnetIds': ['subnet-sl-sibling', 'subnet-sl-other']}
        for b in ('mq-own', 'mq-other')
    ]

    mq._attach_security_groups(neo4j_session, brokers, OWN, TAG)
    mq._attach_subnets(neo4j_session, brokers, OWN, WORKSPACE, TAG)

    assert _links(neo4j_session, 'mq-own') == {
        ('MEMBER_OF_EC2_SECURITY_GROUP', 'sg-sl-new'), ('PART_OF_SUBNET', 'subnet-sl-sibling'),
    }
    assert _links(neo4j_session, 'mq-other') == set()


def test_msk_clusters_link_only_inside_the_workspace(neo4j_session):
    _seed(neo4j_session, 'MSKCluster', 'msk-own', 'msk-other')
    clusters = [
        {'ClusterArn': c, 'SecurityGroups': ['sg-sl-new'], 'SubnetIds': ['subnet-sl-sibling', 'subnet-sl-other']}
        for c in ('msk-own', 'msk-other')
    ]

    msk._attach_security_groups(neo4j_session, clusters, OWN, TAG)
    msk._attach_subnets(neo4j_session, clusters, OWN, WORKSPACE, TAG)

    assert _links(neo4j_session, 'msk-own') == {
        ('MEMBER_OF_EC2_SECURITY_GROUP', 'sg-sl-new'), ('PART_OF_SUBNET', 'subnet-sl-sibling'),
    }
    assert _links(neo4j_session, 'msk-other') == set()


def test_redshift_cluster_links_attach_only_to_the_accounts_cluster(neo4j_session):
    _seed(neo4j_session, 'RedshiftCluster', 'rs-own', 'rs-other')
    clusters = [
        {
            'arn': c, 'VpcId': f'vpc-{c}', 'VpcSecurityGroups': [{'VpcSecurityGroupId': f'sg-{c}'}],
            'IamRoles': [{'IamRoleArn': f'role-{c}'}],
            'VpcEndpoints': [{'NetworkInterfaces': [{'NetworkInterfaceId': f'eni-{c}', 'SubnetId': f'subnet-{c}'}]}],
        }
        for c in ('rs-own', 'rs-other')
    ]

    redshift._attach_ec2_security_groups(neo4j_session, clusters, TAG, OWN)
    redshift._attach_iam_roles(neo4j_session, clusters, TAG, OWN)
    redshift._attach_aws_vpc(neo4j_session, clusters, TAG, OWN)
    redshift._attach_aws_network_interface(neo4j_session, clusters, TAG, OWN)
    redshift._attach_aws_ec2_subnet(neo4j_session, clusters, TAG, OWN)

    assert {rel for rel, _ in _links(neo4j_session, 'rs-own')} == {
        'MEMBER_OF_EC2_SECURITY_GROUP', 'STS_ASSUMEROLE_ALLOW', 'MEMBER_OF_AWS_VPC', 'NETWORK_INTERFACE',
        'CLUSTER_SUBNET',
    }
    assert _links(neo4j_session, 'rs-other') == set()
