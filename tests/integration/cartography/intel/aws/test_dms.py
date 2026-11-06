import cartography.intel.aws.dms
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777793'
OTHER_ACCOUNT_ID = '888888888893'


def _instance(account_id, name, **overrides):
    # Shape of transform_replication_instances() output.
    return {
        'arn': f'arn:aws:dms:us-east-1:{account_id}:rep:{name}', 'region': 'us-east-1', 'consolelink': None,
        'identifier': name, 'instanceClass': 'dms.t3.micro', 'status': 'available', 'engineVersion': '3.5.3',
        'publiclyAccessible': False, 'autoMinorVersionUpgrade': True, 'multiAz': False, 'kmsKeyId': None,
        'networkType': 'IPV4', 'availabilityZone': 'us-east-1a', 'publicIpAddresses': [],
        'privateIpAddresses': ['10.0.0.5'], 'securityGroupIds': [], 'subnetGroupIdentifier': 'default',
        'vpcId': 'vpc-1', 'subnetIds': [], **overrides,
    }


def _endpoint(account_id, name, **overrides):
    # Shape of transform_endpoints() output.
    return {
        'arn': f'arn:aws:dms:us-east-1:{account_id}:endpoint:{name}', 'region': 'us-east-1', 'consolelink': None,
        'identifier': name, 'endpointType': 'SOURCE', 'engineName': 'postgres', 'serverName': 'db.internal',
        'port': 5432, 'databaseName': 'app', 'status': 'active', 'sslMode': 'none', 'certificateArn': None,
        'kmsKeyId': None, **overrides,
    }


def _network(neo4j_session, account_id, sg_ids, subnet_ids):
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        UNWIND $sg_ids AS sg_id
            MERGE (a)-[:RESOURCE]->(:EC2SecurityGroup{id: sg_id})
        """,
        account_id=account_id, sg_ids=sg_ids,
    )
    neo4j_session.run(
        """
        MATCH (a:AWSAccount{id: $account_id})
        UNWIND $subnet_ids AS subnet_id
            MERGE (a)-[:RESOURCE]->(:EC2Subnet{subnetid: subnet_id})
        """,
        account_id=account_id, subnet_ids=subnet_ids,
    )


def test_load_dms_resources_and_cleanup_only_this_account(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-dms', 'o-dms', ACCOUNT_ID)
    create_test_org_account(neo4j_session, 'ws-dms-other', 'o-dms-other', OTHER_ACCOUNT_ID)
    load_instances = cartography.intel.aws.dms.load_replication_instances
    load_endpoints = cartography.intel.aws.dms.load_endpoints
    load_instances(neo4j_session, [_instance(OTHER_ACCOUNT_ID, 'dms-other')], OTHER_ACCOUNT_ID, TEST_UPDATE_TAG - 1)
    load_instances(neo4j_session, [_instance(ACCOUNT_ID, 'dms-gone')], ACCOUNT_ID, TEST_UPDATE_TAG - 1)
    load_endpoints(neo4j_session, [_endpoint(ACCOUNT_ID, 'dms-ep-gone')], ACCOUNT_ID, TEST_UPDATE_TAG - 1)
    load_instances(
        neo4j_session, [_instance(ACCOUNT_ID, 'dms-rep', publiclyAccessible=True, securityGroupIds=['sg-dms'])],
        ACCOUNT_ID, TEST_UPDATE_TAG,
    )
    load_endpoints(neo4j_session, [_endpoint(ACCOUNT_ID, 'dms-ep', sslMode='require')], ACCOUNT_ID, TEST_UPDATE_TAG)

    cartography.intel.aws.dms.cleanup(
        neo4j_session, exposure_job_parameters('ws-dms', 'o-dms', ACCOUNT_ID, TEST_UPDATE_TAG),
    )

    instances = {
        r['name']: r for r in neo4j_session.run(
            "MATCH (a:AWSAccount)-[:RESOURCE]->(n:DMSReplicationInstance) RETURN a.id AS account, "
            "n.replication_instance_identifier AS name, n.publicly_accessible AS public, "
            "n.security_group_ids AS sgs",
        )
    }
    assert set(instances) == {'dms-rep', 'dms-other'}
    assert (instances['dms-rep']['account'], instances['dms-rep']['public'], instances['dms-rep']['sgs']) == (
        ACCOUNT_ID, True, ['sg-dms'],
    )
    endpoints = [
        (r['name'], r['ssl']) for r in neo4j_session.run(
            "MATCH (:AWSAccount)-[:RESOURCE]->(n:DMSEndpoint) RETURN n.endpoint_identifier AS name, n.ssl_mode AS ssl",
        )
    ]
    assert endpoints == [('dms-ep', 'require')]


def test_link_replication_instance_networks_matches_only_this_account(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-dmsl', 'o-dmsl', ACCOUNT_ID + '1')
    create_test_org_account(neo4j_session, 'ws-dmsl-other', 'o-dmsl-other', OTHER_ACCOUNT_ID + '1')
    account, other = ACCOUNT_ID + '1', OTHER_ACCOUNT_ID + '1'
    _network(neo4j_session, account, ['sg-l1', 'sg-l-stale'], ['subnet-l1'])
    # Another tenant has a security group with the same id: it must not be linked.
    _network(neo4j_session, other, ['sg-l2'], [])
    cartography.intel.aws.dms.load_replication_instances(
        neo4j_session,
        [_instance(account, 'dmsl-rep', securityGroupIds=['sg-l1', 'sg-l2', 'sg-l-missing'], subnetIds=['subnet-l1'])],
        account, TEST_UPDATE_TAG,
    )
    neo4j_session.run(
        "MATCH (n:DMSReplicationInstance{replication_instance_identifier: 'dmsl-rep'}), "
        "(sg:EC2SecurityGroup{id: 'sg-l-stale'}) "
        "MERGE (n)-[:MEMBER_OF_EC2_SECURITY_GROUP{lastupdated: $tag}]->(sg)",
        tag=TEST_UPDATE_TAG - 1,
    )

    cartography.intel.aws.dms.link_replication_instance_networks(
        neo4j_session, exposure_job_parameters('ws-dmsl', 'o-dmsl', account, TEST_UPDATE_TAG),
    )

    linked = {
        (r['rel'], r['target']) for r in neo4j_session.run(
            "MATCH (:DMSReplicationInstance{replication_instance_identifier: 'dmsl-rep'})-[r]->(t) "
            "RETURN type(r) AS rel, coalesce(t.subnetid, t.id) AS target",
        )
    }
    assert linked == {('MEMBER_OF_EC2_SECURITY_GROUP', 'sg-l1'), ('PART_OF_SUBNET', 'subnet-l1')}
