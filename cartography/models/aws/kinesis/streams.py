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
class KinesisStreamNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef('StreamARN')
    arn: PropertyRef = PropertyRef('StreamARN')
    name: PropertyRef = PropertyRef('StreamName')
    consolelink: PropertyRef = PropertyRef('consolelink')
    region: PropertyRef = PropertyRef('Region', set_in_kwargs=True)
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)
    status: PropertyRef = PropertyRef('StreamStatus')
    stream_mode: PropertyRef = PropertyRef('StreamMode')
    retention_period_hours: PropertyRef = PropertyRef('RetentionPeriodHours')
    shard_count: PropertyRef = PropertyRef('OpenShardCount')
    encryption_type: PropertyRef = PropertyRef('EncryptionType')
    encrypted: PropertyRef = PropertyRef('Encrypted')
    key_id: PropertyRef = PropertyRef('KeyId')
    creation_timestamp: PropertyRef = PropertyRef('StreamCreationTimestamp')


@dataclass(frozen=True)
class KinesisStreamToAwsAccountRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
# (:KinesisStream)<-[:RESOURCE]-(:AWSAccount)
class KinesisStreamToAWSAccount(CartographyRelSchema):
    target_node_label: str = 'AWSAccount'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'id': PropertyRef('AWS_ID', set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: KinesisStreamToAwsAccountRelProperties = KinesisStreamToAwsAccountRelProperties()


@dataclass(frozen=True)
class KinesisStreamSchema(CartographyNodeSchema):
    label: str = 'KinesisStream'
    properties: KinesisStreamNodeProperties = KinesisStreamNodeProperties()
    sub_resource_relationship: KinesisStreamToAWSAccount = KinesisStreamToAWSAccount()
