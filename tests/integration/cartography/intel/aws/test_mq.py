import cartography.intel.aws.mq
from cartography.util import run_cleanup_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777771'
ARN = f'arn:aws:mq:us-east-1:{ACCOUNT_ID}:broker:'


def _broker(name, **fields):
    # Shape of get_mq_brokers() output.
    return {
        'BrokerArn': f'{ARN}{name}:b-{name}', 'BrokerId': f'b-{name}', 'BrokerName': name, 'BrokerState': 'RUNNING',
        'EngineType': 'ACTIVEMQ', 'described': True, **fields,
    }


def test_load_mq_brokers_and_cleanup(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-mqi', 'o-mqi', ACCOUNT_ID)
    neo4j_session.run("MERGE (:EC2Subnet{subnetid: 'mqi-subnet-1'})")
    brokers = cartography.intel.aws.mq.transform_mq_brokers(
        [
            _broker(
                'mqi-public', PubliclyAccessible=True, SecurityGroups=['mqi-sg-1'], SubnetIds=['mqi-subnet-1'],
                BrokerInstances=[{'Endpoints': ['ssl://b-mqi-public-1.mq.us-east-1.amazonaws.com:61617']}],
            ),
            _broker('mqi-gone', PubliclyAccessible=False),
        ],
        'us-east-1',
    )
    cartography.intel.aws.mq.load_mq_brokers(neo4j_session, brokers, ACCOUNT_ID, TEST_UPDATE_TAG)
    # Next sync: mqi-gone was deleted in AWS.
    cartography.intel.aws.mq.load_mq_brokers(neo4j_session, brokers[:1], ACCOUNT_ID, TEST_UPDATE_TAG + 1)
    run_cleanup_job(
        'aws_import_mq_cleanup.json', neo4j_session,
        exposure_job_parameters('ws-mqi', 'o-mqi', ACCOUNT_ID, TEST_UPDATE_TAG + 1),
    )

    rows = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(b:AWSMQBroker)
        OPTIONAL MATCH (b)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
        OPTIONAL MATCH (b)-[:PART_OF_SUBNET]->(subnet:EC2Subnet)
        RETURN b.name AS name, b.publicly_accessible AS public, b.engine_type AS engine, b.ports AS ports,
            b.region AS region, collect(DISTINCT sg.id) AS groups, collect(DISTINCT subnet.subnetid) AS subnets
        """,
        account_id=ACCOUNT_ID,
    )
    brokers_in_graph = {r['name']: r for r in rows}
    assert set(brokers_in_graph) == {'mqi-public'}
    public = brokers_in_graph['mqi-public']
    assert (public['public'], public['engine'], public['ports'], public['region']) == (
        True, 'ACTIVEMQ', [61617], 'us-east-1',
    )
    assert (public['groups'], public['subnets']) == (['mqi-sg-1'], ['mqi-subnet-1'])
