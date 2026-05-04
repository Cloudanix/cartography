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
class SubImageAPIKeyNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("app_id")
    client_id: PropertyRef = PropertyRef("client_id")
    role: PropertyRef = PropertyRef("role")
    name: PropertyRef = PropertyRef("name")
    description: PropertyRef = PropertyRef("description")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class SubImageAPIKeyToTenantRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
# (:SubImageTenant)-[:RESOURCE]->(:SubImageAPIKey)
class SubImageAPIKeyToTenantRel(CartographyRelSchema):
    target_node_label: str = "SubImageTenant"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("TENANT_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: SubImageAPIKeyToTenantRelProperties = (
        SubImageAPIKeyToTenantRelProperties()
    )


@dataclass(frozen=True)
class SubImageAPIKeySchema(CartographyNodeSchema):
    label: str = "SubImageAPIKey"
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(["APIKey"])
    properties: SubImageAPIKeyNodeProperties = SubImageAPIKeyNodeProperties()
    sub_resource_relationship: SubImageAPIKeyToTenantRel = SubImageAPIKeyToTenantRel()
