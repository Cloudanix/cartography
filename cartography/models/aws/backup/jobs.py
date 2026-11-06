"""
AWS Backup graph models: backup jobs and protected resources.

They record which resources have a recovery point (a job with a RecoveryPointArn, or an entry in
ListProtectedResources) and how long it is kept. The backup misconfig rules decide from these facts;
no rule logic lives here.
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
class AWSBackupJobNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('BackupJobId')
    backup_job_id: PropertyRef = PropertyRef('BackupJobId')
    resource_arn: PropertyRef = PropertyRef('ResourceArn')
    resource_type: PropertyRef = PropertyRef('ResourceType')
    # None until the job has produced a restore point.
    recovery_point_arn: PropertyRef = PropertyRef('RecoveryPointArn')
    # Retention of the produced recovery point; None means kept until deleted by hand.
    recovery_point_delete_after_days: PropertyRef = PropertyRef('RecoveryPointDeleteAfterDays')
    creation_date: PropertyRef = PropertyRef('CreationDate')
    completion_date: PropertyRef = PropertyRef('CompletionDate')
    state: PropertyRef = PropertyRef('State')
    backup_vault_name: PropertyRef = PropertyRef('BackupVaultName')
    backup_vault_arn: PropertyRef = PropertyRef('BackupVaultArn')
    region: PropertyRef = PropertyRef('Region', set_in_kwargs=True)
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
class AWSBackupJobToAwsAccountRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
# (:AWSBackupJob)<-[:RESOURCE]-(:AWSAccount)
class AWSBackupJobToAWSAccount(CartographyRelSchema):
    target_node_label: str = 'AWSAccount'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'id': PropertyRef('AWS_ID', set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: AWSBackupJobToAwsAccountRelProperties = AWSBackupJobToAwsAccountRelProperties()


@dataclass(frozen=True)
class AWSBackupJobSchema(CartographyNodeSchema):
    label: str = 'AWSBackupJob'
    properties: AWSBackupJobNodeProperties = AWSBackupJobNodeProperties()
    sub_resource_relationship: AWSBackupJobToAWSAccount = AWSBackupJobToAWSAccount()


@dataclass(frozen=True)
class AWSBackupProtectedResourceNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('ResourceArn')
    resource_arn: PropertyRef = PropertyRef('ResourceArn')
    resource_type: PropertyRef = PropertyRef('ResourceType')
    resource_name: PropertyRef = PropertyRef('ResourceName')
    last_backup_time: PropertyRef = PropertyRef('LastBackupTime')
    last_recovery_point_arn: PropertyRef = PropertyRef('LastRecoveryPointArn')
    region: PropertyRef = PropertyRef('Region', set_in_kwargs=True)
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
class AWSBackupProtectedResourceToAwsAccountRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
# (:AWSBackupProtectedResource)<-[:RESOURCE]-(:AWSAccount)
class AWSBackupProtectedResourceToAWSAccount(CartographyRelSchema):
    target_node_label: str = 'AWSAccount'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'id': PropertyRef('AWS_ID', set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: AWSBackupProtectedResourceToAwsAccountRelProperties = (
        AWSBackupProtectedResourceToAwsAccountRelProperties()
    )


@dataclass(frozen=True)
class AWSBackupProtectedResourceSchema(CartographyNodeSchema):
    label: str = 'AWSBackupProtectedResource'
    properties: AWSBackupProtectedResourceNodeProperties = AWSBackupProtectedResourceNodeProperties()
    sub_resource_relationship: AWSBackupProtectedResourceToAWSAccount = AWSBackupProtectedResourceToAWSAccount()
