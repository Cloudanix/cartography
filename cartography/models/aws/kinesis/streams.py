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
    id: PropertyRef = PropertyRef('StreamARN', description="ARN of the Kinesis stream.")
    arn: PropertyRef = PropertyRef('StreamARN', description="ARN of the Kinesis stream.")
    name: PropertyRef = PropertyRef('StreamName', description="Name of the Kinesis stream.")
    consolelink: PropertyRef = PropertyRef('consolelink', description="AWS console URL for the stream.")
    region: PropertyRef = PropertyRef('Region', set_in_kwargs=True, description="AWS region of the stream.")
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)
    status: PropertyRef = PropertyRef('StreamStatus', description="Current status of the stream.")
    stream_mode: PropertyRef = PropertyRef('StreamMode', description="Capacity mode of the stream (PROVISIONED or ON_DEMAND).")
    retention_period_hours: PropertyRef = PropertyRef('RetentionPeriodHours', description="Data retention period of the stream, in hours.")
    shard_count: PropertyRef = PropertyRef('OpenShardCount', description="Number of open shards in the stream.")
    encryption_type: PropertyRef = PropertyRef('EncryptionType', description="Server-side encryption type of the stream.")
    encrypted: PropertyRef = PropertyRef('Encrypted', description="Whether server-side encryption is enabled.")
    key_id: PropertyRef = PropertyRef('KeyId', description="KMS key id or ARN used for server-side encryption.")
    creation_timestamp: PropertyRef = PropertyRef('StreamCreationTimestamp', description="Timestamp when the stream was created.")


@dataclass(frozen=True)
class KinesisStreamToAwsAccountRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
# (:KinesisStream)<-[:RESOURCE]-(:AWSAccount)
class KinesisStreamToAWSAccountRel(CartographyRelSchema):
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
    sub_resource_relationship: KinesisStreamToAWSAccountRel = KinesisStreamToAWSAccountRel()
