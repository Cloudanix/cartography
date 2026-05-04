from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import (
    CartographyNodeProperties,
    CartographyNodeSchema,
    ExtraNodeLabels,
)
from cartography.models.core.relationships import (
    CartographyRelProperties,
    CartographyRelSchema,
    LinkDirection,
    TargetNodeMatcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class EC2KeyPairNodeProperties(CartographyNodeProperties):
    """
    Properties for EC2 keypairs from describe-key-pairs
    """

    id: PropertyRef = PropertyRef("KeyPairArn")
    arn: PropertyRef = PropertyRef("KeyPairArn", extra_index=True)
    keyname: PropertyRef = PropertyRef("KeyName")
    keyfingerprint: PropertyRef = PropertyRef("KeyFingerprint", extra_index=True)
    region: PropertyRef = PropertyRef("Region", set_in_kwargs=True)
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class EC2KeyPairToAWSAccountRelRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class EC2KeyPairToAWSAccountRel(CartographyRelSchema):
    """
    Relationship schema for EC2 keypairs to AWS Accounts
    """

    target_node_label: str = "AWSAccount"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("AWS_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: EC2KeyPairToAWSAccountRelRelProperties = (
        EC2KeyPairToAWSAccountRelRelProperties()
    )


@dataclass(frozen=True)
class EC2KeyPairSchema(CartographyNodeSchema):
    """
    Schema for EC2 keypairs from describe-key-pairs
    """

    label: str = "EC2KeyPair"
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(["KeyPair"])
    properties: EC2KeyPairNodeProperties = EC2KeyPairNodeProperties()
    sub_resource_relationship: EC2KeyPairToAWSAccountRel = EC2KeyPairToAWSAccountRel()
