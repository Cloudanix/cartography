"""AWS Backup graph models — backup jobs and protected resources.

These two node types carry exactly the facts the compliance backup checks consume (rules 50-57):
which resources have an AWS Backup recovery point (a job with a RecoveryPointArn) and which are
currently protected (ListProtectedResources). No rule logic lives here — the consumer decides RPO /
protection; the sync only records the facts.
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


# ---------------------------------------------------------------------------
# AWSBackupJob — one per backup:ListBackupJobs entry.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AWSBackupJobNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('BackupJobId')
    backup_job_id: PropertyRef = PropertyRef('BackupJobId')
    # The protected resource this job backed up, and the recovery point it produced (None until the
    # job has produced a restore point). The compliance check keys off both.
    resource_arn: PropertyRef = PropertyRef('ResourceArn')
    recovery_point_arn: PropertyRef = PropertyRef('RecoveryPointArn')
    creation_date: PropertyRef = PropertyRef('CreationDate')
    completion_date: PropertyRef = PropertyRef('CompletionDate')
    state: PropertyRef = PropertyRef('State')
    backup_vault_name: PropertyRef = PropertyRef('BackupVaultName')
    resource_type: PropertyRef = PropertyRef('ResourceType')
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


# ---------------------------------------------------------------------------
# AWSBackupProtectedResource — one per backup:ListProtectedResources entry.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AWSBackupProtectedResourceNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('ResourceArn')
    resource_arn: PropertyRef = PropertyRef('ResourceArn')
    resource_type: PropertyRef = PropertyRef('ResourceType')
    last_backup_time: PropertyRef = PropertyRef('LastBackupTime')
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
