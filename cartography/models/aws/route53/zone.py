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
class AWSDNSZoneNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("zoneid")
    zoneid: PropertyRef = PropertyRef("zoneid")
    name: PropertyRef = PropertyRef("name", extra_index=True)
    comment: PropertyRef = PropertyRef("comment")
    privatezone: PropertyRef = PropertyRef("privatezone")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AWSDNSZoneToAWSAccountRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AWSDNSZoneToAWSAccountRel(CartographyRelSchema):
    target_node_label: str = "AWSAccount"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("AWS_ID", set_in_kwargs=True)}
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: AWSDNSZoneToAWSAccountRelProperties = (
        AWSDNSZoneToAWSAccountRelProperties()
    )


@dataclass(frozen=True)
class AWSDNSZoneSchema(CartographyNodeSchema):
    label: str = "AWSDNSZone"
    properties: AWSDNSZoneNodeProperties = AWSDNSZoneNodeProperties()
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(["DNSZone"])
    sub_resource_relationship: AWSDNSZoneToAWSAccountRel = AWSDNSZoneToAWSAccountRel()
