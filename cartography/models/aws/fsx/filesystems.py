from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import CartographyNodeProperties
from cartography.models.core.nodes import CartographyNodeSchema
from cartography.models.core.relationships import CartographyRelProperties
from cartography.models.core.relationships import CartographyRelSchema
from cartography.models.core.relationships import LinkDirection
from cartography.models.core.relationships import make_target_node_matcher
from cartography.models.core.relationships import OtherRelationships
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
    storage_type: PropertyRef = PropertyRef('StorageType')
    dns_name: PropertyRef = PropertyRef('DNSName')
    vpc_id: PropertyRef = PropertyRef('VpcId')
    subnet_ids: PropertyRef = PropertyRef('SubnetIds')
    # FSx-native daily backups (not AWS Backup recovery points); > 0 means they are on.
    automatic_backup_retention_days: PropertyRef = PropertyRef('AutomaticBackupRetentionDays')
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
class FSxFileSystemToAWSVpcRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
# (:FSxFileSystem)-[:MEMBER_OF_AWS_VPC]->(:AWSVpc)
class FSxFileSystemToAWSVpc(CartographyRelSchema):
    target_node_label: str = 'AWSVpc'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'id': PropertyRef('VpcId')},
    )
    direction: LinkDirection = LinkDirection.OUTWARD
    rel_label: str = "MEMBER_OF_AWS_VPC"
    properties: FSxFileSystemToAWSVpcRelProperties = FSxFileSystemToAWSVpcRelProperties()


@dataclass(frozen=True)
class FSxFileSystemSchema(CartographyNodeSchema):
    label: str = 'FSxFileSystem'
    properties: FSxFileSystemNodeProperties = FSxFileSystemNodeProperties()
    sub_resource_relationship: FSxFileSystemToAWSAccount = FSxFileSystemToAWSAccount()
    other_relationships: OtherRelationships = OtherRelationships([FSxFileSystemToAWSVpc()])
