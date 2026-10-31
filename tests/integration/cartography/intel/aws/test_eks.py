from unittest.mock import MagicMock
from unittest.mock import patch

import cartography.intel.aws.eks
from cartography.intel.aws.ec2 import instances
from cartography.intel.aws.eks import sync
from cartography.util import run_analysis_job
from tests.data.aws.eks import DESCRIBE_CLUSTERS
from tests.data.aws.eks import LIST_CLUSTERS
from tests.integration.cartography.intel.aws.common import create_test_account
from tests.integration.cartography.intel.aws.common import create_test_org_account
from tests.integration.cartography.intel.aws.common import exposure_job_parameters
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


def _eks_cluster(name, public_access, public_access_cidrs):
    return {
        'name': name,
        'arn': f'arn:aws:eks:us-east-1:333333333333:cluster/{name}',
        'region': 'us-east-1',
        'resourcesVpcConfig': {
            'endpointPublicAccess': public_access,
            'endpointPrivateAccess': True,
            'publicAccessCidrs': public_access_cidrs,
        },
    }


def test_eks_exposure_uses_ingested_public_access_cidrs(neo4j_session):
    account_id = '333333333333'
    create_test_org_account(neo4j_session, 'ws-eks', 'o-eks', account_id)
    clusters = cartography.intel.aws.eks.transform([
        _eks_cluster('eks-open', True, ['0.0.0.0/0']),
        _eks_cluster('eks-allowlisted', True, ['203.0.113.0/24']),
        _eks_cluster('eks-private-only', False, ['0.0.0.0/0']),
    ])
    cartography.intel.aws.eks.load_eks_clusters(neo4j_session, clusters, account_id, TEST_UPDATE_TAG)

    run_analysis_job(
        'aws_eks_asset_exposure.json', neo4j_session,
        exposure_job_parameters('ws-eks', 'o-eks', account_id, TEST_UPDATE_TAG + 1),
    )

    result = neo4j_session.run(
        """
        MATCH (:AWSAccount{id: $account_id})-[:RESOURCE]->(c:EKSCluster{exposed_internet: true})
        RETURN c.name AS name, c.exposed_internet_type AS types, c.endpoint_private_access AS private_access,
               c.publicContext IS NOT NULL AS has_context
        """,
        account_id=account_id,
    )
    assert {r['name']: (r['types'], r['private_access'], r['has_context']) for r in result} == {
        'eks-open': (['direct_ipv4'], True, True),
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
