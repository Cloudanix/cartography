from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.relationships import (
    CartographyRelProperties,
    CartographyRelSchema,
    LinkDirection,
    TargetNodeMatcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class AWSGroupToAWSUserRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AWSGroupToAWSUserRel(CartographyRelSchema):
    # AWSUser -MEMBER_AWS_GROUP-> AWSGroup
    target_node_label: str = "AWSUser"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {
            "arn": PropertyRef("user_arns", one_to_many=True),
        }
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "MEMBER_AWS_GROUP"
    properties: AWSGroupToAWSUserRelProperties = AWSGroupToAWSUserRelProperties()
