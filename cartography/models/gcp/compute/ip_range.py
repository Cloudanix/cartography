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
    OtherRelationships,
    TargetNodeMatcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class IpRangeNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("range")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    range: PropertyRef = PropertyRef("range", extra_index=True)


@dataclass(frozen=True)
class IpRangeToIpRuleRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class IpRangeToIpRuleRel(CartographyRelSchema):
    target_node_label: str = "GCPIpRule"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {
            "id": PropertyRef("ruleid"),
        }
    )
    direction: LinkDirection = LinkDirection.OUTWARD
    rel_label: str = "MEMBER_OF_IP_RULE"
    properties: IpRangeToIpRuleRelProperties = IpRangeToIpRuleRelProperties()


@dataclass(frozen=True)
class IpRangeToProjectRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class IpRangeToProjectRel(CartographyRelSchema):
    target_node_label: str = "GCPProject"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {
            "id": PropertyRef("PROJECT_ID", set_in_kwargs=True),
        }
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: IpRangeToProjectRelProperties = IpRangeToProjectRelProperties()


@dataclass(frozen=True)
class IpRangeSchema(CartographyNodeSchema):
    label: str = "GCPIpRange"
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(["IpRange"])
    properties: IpRangeNodeProperties = IpRangeNodeProperties()
    sub_resource_relationship: IpRangeToProjectRel = IpRangeToProjectRel()
    other_relationships: OtherRelationships = OtherRelationships(
        [
            IpRangeToIpRuleRel(),
        ]
    )
