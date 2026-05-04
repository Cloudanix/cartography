from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import (
    CartographyNodeProperties,
    CartographyNodeSchema,
)
from cartography.models.core.relationships import (
    CartographyRelProperties,
    CartographyRelSchema,
    LinkDirection,
    TargetNodeMatcher,
    make_target_node_matcher,
)


# Test defining a simple node with no relationships.
@dataclass(frozen=True)
class SimpleNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("Id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    property1: PropertyRef = PropertyRef("property1")
    property2: PropertyRef = PropertyRef("property2")


@dataclass(frozen=True)
class SimpleNodeSchema(CartographyNodeSchema):
    label: str = "SimpleNode"
    properties: SimpleNodeProperties = SimpleNodeProperties()


# Test defining a simple node with a sub resource rel: (:SimpleNode)<-[:RESOURCE]-(:SubResource)
@dataclass(frozen=True)
class SimpleNodeToSubResourceRelProps(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class SimpleNodeToSubResourceRel(CartographyRelSchema):
    target_node_label: str = "SubResource"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("sub_resource_id", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RELATIONSHIP_LABEL"
    properties: SimpleNodeToSubResourceRelProps = SimpleNodeToSubResourceRelProps()


@dataclass(frozen=True)
class SimpleNodeWithSubResourceSchema(CartographyNodeSchema):
    label: str = "SimpleNode"
    properties: SimpleNodeProperties = SimpleNodeProperties()
    sub_resource_relationship: SimpleNodeToSubResourceRel = SimpleNodeToSubResourceRel()
