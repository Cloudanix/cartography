from unittest.mock import MagicMock
from unittest.mock import patch

import cartography.intel.aws.eks
from cartography.intel.aws.ec2 import instances
from cartography.intel.aws.eks import sync
from tests.data.aws.eks import DESCRIBE_CLUSTERS
from tests.data.aws.eks import LIST_CLUSTERS
from tests.integration.cartography.intel.aws.common import create_test_account
from tests.integration.util import check_nodes
from tests.integration.util import check_rels

TEST_ACCOUNT_ID = '000000000000'
TEST_REGION = 'eu-west-1'
TEST_UPDATE_TAG = 123456789
TEST_WORKSPACE_ID = '12345'


@patch.object(cartography.intel.aws.eks, 'get_eks_clusters', return_value=LIST_CLUSTERS)
@patch.object(cartography.intel.aws.eks, 'get_eks_describe_cluster', side_effect=DESCRIBE_CLUSTERS)
def test_sync_eks_clusters(mock_describe_clusters, mock_get_clusters, neo4j_session):
    # Arrange
    create_test_account(neo4j_session, TEST_ACCOUNT_ID, TEST_UPDATE_TAG)
    boto3_session = MagicMock()

    # Act
    sync(
        neo4j_session,
        boto3_session,
        [TEST_REGION],
        TEST_ACCOUNT_ID,
        TEST_UPDATE_TAG,
        {'UPDATE_TAG': TEST_UPDATE_TAG, 'AWS_ID': TEST_ACCOUNT_ID},
    )

    # Assert
    assert check_nodes(neo4j_session, 'EKSCluster', ['id', 'platform_version']) == {
        ('arn:aws:eks:eu-west-1:111111111111:cluster/cluster_1', 'eks.9'),
        ('arn:aws:eks:eu-west-2:222222222222:cluster/cluster_2', 'eks.9'),
    }

    assert check_rels(
        neo4j_session,
        'EKSCluster',
        'id',
        'AWSAccount',
        'id',
        'RESOURCE',
        rel_direction_right=False,
    ) == {
        ('arn:aws:eks:eu-west-1:111111111111:cluster/cluster_1', '000000000000'),
        ('arn:aws:eks:eu-west-2:222222222222:cluster/cluster_2', '000000000000'),
    }


def test_sync_eks_node_links_scoped_to_workspace_account_region(neo4j_session):
    # Same cluster name 'prod' exists in another region of this account and in another
    # workspace's account. Only the same account+region cluster may get the HAS_NODE edge.
    neo4j_session.run(
        """
        MERGE (w1:CloudanixWorkspace{id: 'eksl-w1'})-[:OWNER]->(a1:AWSAccount{id: 'eksl-a1'})
        MERGE (w2:CloudanixWorkspace{id: 'eksl-w2'})-[:OWNER]->(a2:AWSAccount{id: 'eksl-a2'})
        MERGE (a1)-[:RESOURCE]->(c1:EKSCluster{id: 'eksl-c1', name: 'prod', region: 'us-east-1'})
        MERGE (a1)-[:RESOURCE]->(:EKSCluster{id: 'eksl-c1-eu', name: 'prod', region: 'eu-west-1'})
        MERGE (a2)-[:RESOURCE]->(:EKSCluster{id: 'eksl-c2', name: 'prod', region: 'us-east-1'})
        MERGE (c1)<-[:ASSOCIATED_WITH]-(:EKSClusterNodeGroup{id: 'eksl-ng1', name: 'ng1'})
        MERGE (a1)-[:RESOURCE]->(:EC2Instance{
            id: 'eksl-i1', region: 'us-east-1', eksclustername: 'prod', eksnodegroupname: 'ng1'
        })
        MERGE (a1)-[:RESOURCE]->(:EC2Instance{id: 'eksl-i2', region: 'us-east-1', eksclustername: 'prod'})
        MERGE (a2)-[:RESOURCE]->(:EC2Instance{id: 'eksl-i3', region: 'us-east-1', eksclustername: 'prod'})
        MERGE (a1)-[:RESOURCE]->(old:EC2Instance{id: 'eksl-old', region: 'us-east-1'})
        MERGE (c1)-[:HAS_NODE{lastupdated: 1}]->(old)
        """,
    )

    instances.sync_eks_node_links(
        neo4j_session,
        {'WORKSPACE_ID': 'eksl-w1', 'AWS_ID': 'eksl-a1', 'UPDATE_TAG': TEST_UPDATE_TAG},
    )

    links = {
        (r['s'], r['i']) for r in neo4j_session.run(
            """
            MATCH (s)-[:HAS_NODE]->(i:EC2Instance) WHERE i.id STARTS WITH 'eksl-'
            RETURN s.id AS s, i.id AS i
            """,
        )
    }
    assert links == {('eksl-c1', 'eksl-i1'), ('eksl-c1', 'eksl-i2'), ('eksl-ng1', 'eksl-i1')}
