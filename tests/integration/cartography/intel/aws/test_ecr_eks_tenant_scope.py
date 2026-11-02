"""ECR repository images and EKS node group auto scaling links reach only the syncing account's nodes."""
from cartography.intel.aws import ecr
from cartography.intel.aws import eks
from tests.integration.cartography.intel.aws.common import create_test_org_account

TAG = 100
OWN, OTHER = 'ee-own', 'ee-other'


def _seed(neo4j_session):
    create_test_org_account(neo4j_session, 'ee-ws-own', 'ee-org-own', OWN)
    create_test_org_account(neo4j_session, 'ee-ws-other', 'ee-org-other', OTHER)
    neo4j_session.run(
        """
        MATCH (own:AWSAccount{id: $own}), (other:AWSAccount{id: $other})
        MERGE (own)-[:RESOURCE]->(:ECRRepository{id: 'repo-own', uri: 'uri-own'})
        MERGE (other)-[:RESOURCE]->(:ECRRepository{id: 'repo-other', uri: 'uri-other'})
        MERGE (own)-[:RESOURCE]->(:EKSCluster{id: 'cl-own'})
            <-[:ASSOCIATED_WITH]-(:EKSClusterNodeGroup{arn: 'ng-own'})
        MERGE (other)-[:RESOURCE]->(:EKSCluster{id: 'cl-other'})
            <-[:ASSOCIATED_WITH]-(:EKSClusterNodeGroup{arn: 'ng-other'})
        """,
        own=OWN, other=OTHER,
    )


def test_ecr_repository_images_attach_only_to_the_accounts_repository(neo4j_session):
    _seed(neo4j_session)

    ecr.load_ecr_repository_images(
        neo4j_session,
        [
            {'repo_uri': uri, 'imageTag': 'latest', 'imageDigest': f'sha256:{uri}', 'region': 'us-east-1'}
            for uri in ('uri-own', 'uri-other')
        ],
        TAG, OWN,
    )

    linked = neo4j_session.run("MATCH (r:ECRRepository)-[:REPO_IMAGE]->(ri) RETURN r.uri AS r, ri.uri AS ri")
    assert {(r['r'], r['ri']) for r in linked} == {('uri-own', 'uri-own:latest')}


def test_eks_auto_scaling_groups_attach_only_to_the_accounts_node_group(neo4j_session):
    _seed(neo4j_session)

    for nodegroup in ('ng-own', 'ng-other'):
        eks.attact_autoscaling_groups_to_nodegroups(
            neo4j_session, nodegroup, [{'AutoScalingGroupARN': f'asg-{nodegroup}'}], OWN, TAG,
        )

    linked = neo4j_session.run(
        "MATCH (g:AutoScalingGroup)-[:ASSOCIATED_WITH]->(ng:EKSClusterNodeGroup) RETURN g.arn AS g, ng.arn AS ng",
    )
    assert {(r['g'], r['ng']) for r in linked} == {('asg-ng-own', 'ng-own')}
