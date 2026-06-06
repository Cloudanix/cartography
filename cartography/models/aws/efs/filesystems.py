"""AWS EFS graph model — Elastic File System.

Carries the facts the compliance EFS checks consume (rules 55/56 + the EFS encryption/CMK rules):
file system identity, creation time (for the backup RPO grace), and encryption.
"""

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
class EFSFileSystemNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('FileSystemArn')
    arn: PropertyRef = PropertyRef('FileSystemArn')
    file_system_id: PropertyRef = PropertyRef('FileSystemId')
    name: PropertyRef = PropertyRef('Name')
    creation_time: PropertyRef = PropertyRef('CreationTime')
    encrypted: PropertyRef = PropertyRef('Encrypted')
    kms_key_id: PropertyRef = PropertyRef('KmsKeyId')
    life_cycle_state: PropertyRef = PropertyRef('LifeCycleState')
    number_of_mount_targets: PropertyRef = PropertyRef('NumberOfMountTargets')
    consolelink: PropertyRef = PropertyRef('consolelink')
    region: PropertyRef = PropertyRef('Region', set_in_kwargs=True)
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
class EFSFileSystemToAwsAccountRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
# (:EFSFileSystem)<-[:RESOURCE]-(:AWSAccount)
class EFSFileSystemToAWSAccount(CartographyRelSchema):
    target_node_label: str = 'AWSAccount'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'id': PropertyRef('AWS_ID', set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: EFSFileSystemToAwsAccountRelProperties = EFSFileSystemToAwsAccountRelProperties()


@dataclass(frozen=True)
class EFSFileSystemSchema(CartographyNodeSchema):
    label: str = 'EFSFileSystem'
    properties: EFSFileSystemNodeProperties = EFSFileSystemNodeProperties()
    sub_resource_relationship: EFSFileSystemToAWSAccount = EFSFileSystemToAWSAccount()
