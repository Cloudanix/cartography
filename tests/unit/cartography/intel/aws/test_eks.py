from cartography.intel.aws.eks import transform
from cartography.models.aws.eks.clusters import EKSClusterNodeProperties


def _cluster(**vpc_config):
    return {'name': 'c1', 'arn': 'arn:aws:eks:us-east-1:111111111111:cluster/c1', 'resourcesVpcConfig': vpc_config}


def test_transform_lifts_endpoint_access_settings():
    [cluster] = transform([
        _cluster(endpointPublicAccess=True, endpointPrivateAccess=False, publicAccessCidrs=['0.0.0.0/0']),
    ])

    assert cluster['clusterEndpointPublic'] is True
    assert cluster['clusterEndpointPrivate'] is False
    assert cluster['publicAccessCidrs'] == ['0.0.0.0/0']


def test_transform_leaves_missing_endpoint_access_settings_unset():
    [cluster] = transform([{'name': 'c1', 'arn': 'arn:aws:eks:us-east-1:111111111111:cluster/c1'}])

    assert cluster['clusterEndpointPublic'] is None
    assert cluster['clusterEndpointPrivate'] is None
    assert cluster['publicAccessCidrs'] is None


def test_cluster_schema_stores_endpoint_access_settings():
    # aws_eks_asset_exposure.json keys on public_access_cidrs; publicContext reads endpoint_private_access.
    properties = EKSClusterNodeProperties()

    assert properties.public_access_cidrs.name == 'publicAccessCidrs'
    assert properties.endpoint_private_access.name == 'clusterEndpointPrivate'
