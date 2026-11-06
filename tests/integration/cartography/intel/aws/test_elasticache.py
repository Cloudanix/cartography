import cartography.intel.aws.elasticache
import tests.data.aws.elasticache
from cartography.util import run_analysis_job
from tests.integration.cartography.intel.aws.common import create_test_org_account

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'us-east-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = '12345'


def test_load_clusters(neo4j_session):
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
    elasticache_data = tests.data.aws.elasticache.DESCRIBE_CACHE_CLUSTERS
    clusters = elasticache_data['CacheClusters']
    cartography.intel.aws.elasticache.load_elasticache_clusters(
        neo4j_session,
        clusters,
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
    )

    expected_cluster_arns = {cluster['ARN'] for cluster in clusters}
    nodes = neo4j_session.run(
        """
        MATCH (r:ElasticacheCluster) RETURN r.arn
        """,
    )
    actual_cluster_arns = {n['r.arn'] for n in nodes}
    assert actual_cluster_arns == expected_cluster_arns

    # Test the connection to the account
    expected_cluster_arns = {(cluster['ARN'], TEST_ACCOUNT_ID) for cluster in clusters}
    nodes = neo4j_session.run(
        """
        MATCH (r:ElasticacheCluster)<-[:RESOURCE]-(a:AWSAccount) RETURN r.arn, a.id
        """,
    )
    actual_cluster_arns = {(n['r.arn'], n['a.id']) for n in nodes}
    assert actual_cluster_arns == expected_cluster_arns

    # Test undefined topic_arns
    topic_arns_in_test_data = {cluster.get('NotificationConfiguration', {}).get('TopicArn') for cluster in clusters}
    expected_topic_arns = {topic for topic in topic_arns_in_test_data if topic}  # Filter out Nones.
    nodes = neo4j_session.run(
        """
        MATCH (r:ElasticacheTopic) RETURN r.arn
        """,
    )
    actual_topic_arns = {n['r.arn'] for n in nodes}
    assert actual_topic_arns == expected_topic_arns


EXPOSURE_ACCOUNT_ID = '333344445555'
EXPOSURE_JOB_PARAMETERS = {
    'UPDATE_TAG': TEST_UPDATE_TAG + 1,
    'AWS_ID': EXPOSURE_ACCOUNT_ID,
    'ORGANIZATION_ID': 'o-elasticache-exposure',
    'WORKSPACE_ID': 'ws-elasticache-exposure',
    'LIMIT_SIZE': 100,
}


def test_elasticache_cluster_exposure_never_public(neo4j_session):
    # ElastiCache nodes have no public address and are reachable only from inside the VPC, so an
    # open security group does not make a cluster internet exposed. The job only clears old flags.
    create_test_org_account(
        neo4j_session, EXPOSURE_JOB_PARAMETERS['WORKSPACE_ID'], EXPOSURE_JOB_PARAMETERS['ORGANIZATION_ID'],
        EXPOSURE_ACCOUNT_ID,
    )
    neo4j_session.run(
        """
        MATCH (aa:AWSAccount{id: $account_id})
        MERGE (sg:EC2SecurityGroup{id: 'sg-elasticache-exposure-open'})
        // Both id shapes: the job matched IpRange{id: '0.0.0.0/0'}, ingestion writes IpRule/<rule>/ipRange/<cidr>.
        MERGE (:IpRange{id: '0.0.0.0/0', range: '0.0.0.0/0'})-[:MEMBER_OF_IP_RULE]->
              (rule:IpPermissionInbound{ruleid: 'sg-elasticache-exposure-open/tcp/6379'})
              -[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        MERGE (:IpRange{id: 'IpRule/sg-elasticache-exposure-open/tcp/6379/ipRange/0.0.0.0/0', range: '0.0.0.0/0'})
              -[:MEMBER_OF_IP_RULE]->(rule)
        MERGE (:Ipv6Range{id: '::/0', range: '::/0'})-[:MEMBER_OF_IP_RULE]->(rule)
        WITH aa, sg
        UNWIND $clusters AS c
        MERGE (aa)-[:RESOURCE]->(cluster:ElasticacheCluster{id: c.id})
        SET cluster.exposed_internet = c.stale, cluster.exposed_internet_type = c.types,
            cluster.publicContext = c.context
        MERGE (cluster)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
        """,
        account_id=EXPOSURE_ACCOUNT_ID, clusters=[
            {'id': 'elasticache-exposure-open-sg', 'stale': None, 'types': None, 'context': None},
            # Flagged by an earlier run.
            {
                'id': 'elasticache-exposure-stale', 'stale': True, 'types': ['direct_ipv4'],
                'context': '[{"resource": "elasticache-exposure-stale"}]',
            },
        ],
    )

    run_analysis_job('aws_elasticache_cluster_asset_exposure.json', neo4j_session, EXPOSURE_JOB_PARAMETERS)

    nodes = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(c:ElasticacheCluster)
        RETURN c.id AS id, c.exposed_internet AS exposed, c.exposed_internet_type AS types, c.publicContext AS context
        """,
        account_id=EXPOSURE_ACCOUNT_ID,
    )
    assert {n['id']: (n['exposed'], n['types'], n['context']) for n in nodes} == {
        'elasticache-exposure-open-sg': (None, None, None),
        'elasticache-exposure-stale': (None, None, None),
    }
