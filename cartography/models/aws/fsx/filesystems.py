"""AWS FSx graph model — FSx file systems.

Carries the facts the compliance FSx checks consume (rule 57): identity and creation time (for the
backup RPO grace).
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
class FSxFileSystemNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('ResourceARN')
    arn: PropertyRef = PropertyRef('ResourceARN')
    file_system_id: PropertyRef = PropertyRef('FileSystemId')
    file_system_type: PropertyRef = PropertyRef('FileSystemType')
    creation_time: PropertyRef = PropertyRef('CreationTime')
    lifecycle: PropertyRef = PropertyRef('Lifecycle')
    kms_key_id: PropertyRef = PropertyRef('KmsKeyId')
    storage_capacity: PropertyRef = PropertyRef('StorageCapacity')
    consolelink: PropertyRef = PropertyRef('consolelink')
    region: PropertyRef = PropertyRef('Region', set_in_kwargs=True)
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
class FSxFileSystemToAwsAccountRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
# (:FSxFileSystem)<-[:RESOURCE]-(:AWSAccount)
class FSxFileSystemToAWSAccount(CartographyRelSchema):
    target_node_label: str = 'AWSAccount'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'id': PropertyRef('AWS_ID', set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: FSxFileSystemToAwsAccountRelProperties = FSxFileSystemToAwsAccountRelProperties()


@dataclass(frozen=True)
class FSxFileSystemSchema(CartographyNodeSchema):
    label: str = 'FSxFileSystem'
    properties: FSxFileSystemNodeProperties = FSxFileSystemNodeProperties()
    sub_resource_relationship: FSxFileSystemToAWSAccount = FSxFileSystemToAWSAccount()
