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
class ScalewayPermissionSetNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    name: PropertyRef = PropertyRef("name", extra_index=True)
    scope_type: PropertyRef = PropertyRef("scope_type")
    description: PropertyRef = PropertyRef("description")
    categories: PropertyRef = PropertyRef("categories")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class ScalewayPermissionSetToOrganizationRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
# (:ScalewayOrganization)-[:RESOURCE]->(:ScalewayPermissionSet)
class ScalewayPermissionSetToOrganizationRel(CartographyRelSchema):
    target_node_label: str = "ScalewayOrganization"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("ORG_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: ScalewayPermissionSetToOrganizationRelProperties = (
        ScalewayPermissionSetToOrganizationRelProperties()
    )


@dataclass(frozen=True)
class ScalewayPermissionSetSchema(CartographyNodeSchema):
    label: str = "ScalewayPermissionSet"
    properties: ScalewayPermissionSetNodeProperties = (
        ScalewayPermissionSetNodeProperties()
    )
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(["PermissionRole"])
    sub_resource_relationship: ScalewayPermissionSetToOrganizationRel = (
        ScalewayPermissionSetToOrganizationRel()
    )
