from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.relationships import (
    CartographyRelProperties,
    CartographyRelSchema,
    LinkDirection,
    SourceNodeMatcher,
    TargetNodeMatcher,
    make_source_node_matcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class STSAssumeRoleAllowRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    _sub_resource_label: PropertyRef = PropertyRef(
        "_sub_resource_label", set_in_kwargs=True
    )
    _sub_resource_id: PropertyRef = PropertyRef("_sub_resource_id", set_in_kwargs=True)


@dataclass(frozen=True)
class STSAssumeRoleAllowMatchLink(CartographyRelSchema):
    rel_label: str = "STS_ASSUMEROLE_ALLOW"
    direction: LinkDirection = LinkDirection.OUTWARD
    properties: STSAssumeRoleAllowRelProperties = STSAssumeRoleAllowRelProperties()

    # Target node (the role being assumed)
    target_node_label: str = "AWSRole"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"arn": PropertyRef("target_arn")},
    )

    # Source node (the principal that can assume the role)
    source_node_label: str = "AWSPrincipal"
    source_node_matcher: SourceNodeMatcher = make_source_node_matcher(
        {"arn": PropertyRef("source_arn")},
    )
