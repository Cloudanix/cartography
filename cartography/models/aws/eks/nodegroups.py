from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import CartographyNodeProperties
from cartography.models.core.nodes import CartographyNodeSchema
from cartography.models.core.relationships import CartographyRelProperties
from cartography.models.core.relationships import CartographyRelSchema
from cartography.models.core.relationships import LinkDirection
from cartography.models.core.relationships import make_target_node_matcher
from cartography.models.core.relationships import TargetNodeMatcher


@dataclass(frozen=True)
class EKSClusterNodeGroupNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('nodegroupArn', description="ARN of the EKS node group.")
    consolelink: PropertyRef = PropertyRef('consolelink', description="AWS console URL for the node group.")
    arn: PropertyRef = PropertyRef('nodegroupArn', extra_index=True, description="ARN of the EKS node group.")
    name: PropertyRef = PropertyRef('nodegroupName', extra_index=True, description="Name of the EKS node group.")
    region: PropertyRef = PropertyRef('region', description="AWS region of the node group.")
    created_at: PropertyRef = PropertyRef('createdAt', description="Timestamp when the node group was created.")
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)
    cluster_name: PropertyRef = PropertyRef('clusterName', description="Name of the EKS cluster this node group belongs to.")
    capacity_type: PropertyRef = PropertyRef('capacityType', description="Capacity type of the node group (ON_DEMAND or SPOT).")
    node_role: PropertyRef = PropertyRef('nodeRole', description="IAM role ARN used by the node group's worker nodes.")
    version: PropertyRef = PropertyRef('version', description="Kubernetes version of the node group.")
    release_ersion: PropertyRef = PropertyRef('releaseVersion', description="AMI release version of the node group (field name kept for graph compatibility).")
    status: PropertyRef = PropertyRef('status', description="Current status of the node group.")
    ami_type: PropertyRef = PropertyRef('amiType', description="AMI type of the node group.")
    disk_tize: PropertyRef = PropertyRef('diskSize', description="Root disk size in GiB (field name kept for graph compatibility).")


@dataclass(frozen=True)
class EKSClusterNodeGroupToEKSClusterRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
class EKSClusterNodeGroupToEKSClusterRel(CartographyRelSchema):
    target_node_label: str = 'EKSCluster'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'id': PropertyRef('cluster_arn', set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.OUTWARD
    rel_label: str = "ASSOCIATED_WITH"
    properties: EKSClusterNodeGroupToEKSClusterRelProperties = EKSClusterNodeGroupToEKSClusterRelProperties()


@dataclass(frozen=True)
class EKSClusterNodeGroupSchema(CartographyNodeSchema):
    label: str = 'EKSClusterNodeGroup'
    properties: EKSClusterNodeGroupNodeProperties = EKSClusterNodeGroupNodeProperties()
    sub_resource_relationship: EKSClusterNodeGroupToEKSClusterRel = EKSClusterNodeGroupToEKSClusterRel()
