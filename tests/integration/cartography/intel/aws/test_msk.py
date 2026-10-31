import cartography.intel.aws.msk
from cartography.util import run_cleanup_job
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters

TEST_UPDATE_TAG = 123456789
ACCOUNT_ID = '777777777773'


def _cluster(name, **provisioned):
    # Shape of one ListClustersV2 ClusterInfo.
    return {
        'ClusterArn': f'arn:aws:kafka:us-east-1:{ACCOUNT_ID}:cluster/{name}/uuid', 'ClusterName': name,
        'ClusterType': 'PROVISIONED', 'State': 'ACTIVE', 'Provisioned': {'BrokerNodeGroupInfo': provisioned},
    }


def test_load_msk_clusters_and_cleanup(neo4j_session):
    create_test_org_account(neo4j_session, 'ws-mski', 'o-mski', ACCOUNT_ID)
    neo4j_session.run("MERGE (:EC2Subnet{subnetid: 'mski-subnet-1'})")
    clusters = cartography.intel.aws.msk.transform_msk_clusters(
        [
            _cluster(
                'mski-public', SecurityGroups=['mski-sg-1'], ClientSubnets=['mski-subnet-1'],
                ConnectivityInfo={'PublicAccess': {'Type': 'SERVICE_PROVIDED_EIPS'}},
            ),
            _cluster('mski-gone'),
        ],
        'us-east-1',
    )
    cartography.intel.aws.msk.load_msk_clusters(neo4j_session, clusters, ACCOUNT_ID, TEST_UPDATE_TAG)
    # Next sync: mski-gone was deleted in AWS.
    cartography.intel.aws.msk.load_msk_clusters(neo4j_session, clusters[:1], ACCOUNT_ID, TEST_UPDATE_TAG + 1)
    run_cleanup_job(
        'aws_import_msk_cleanup.json', neo4j_session,
        exposure_job_parameters('ws-mski', 'o-mski', ACCOUNT_ID, TEST_UPDATE_TAG + 1),
    )

    rows = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(c:MSKCluster)
        OPTIONAL MATCH (c)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg:EC2SecurityGroup)
        OPTIONAL MATCH (c)-[:PART_OF_SUBNET]->(subnet:EC2Subnet)
        RETURN c.name AS name, c.public_access_type AS public_access, c.cluster_type AS type, c.region AS region,
            collect(DISTINCT sg.id) AS groups, collect(DISTINCT subnet.subnetid) AS subnets
        """,
        account_id=ACCOUNT_ID,
    )
    clusters_in_graph = {r['name']: r for r in rows}
    assert set(clusters_in_graph) == {'mski-public'}
    public = clusters_in_graph['mski-public']
    assert (public['public_access'], public['type'], public['region']) == (
        'SERVICE_PROVIDED_EIPS', 'PROVISIONED', 'us-east-1',
    )
    assert (public['groups'], public['subnets']) == (['mski-sg-1'], ['mski-subnet-1'])
