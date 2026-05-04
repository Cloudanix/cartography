from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import (
    CartographyNodeProperties,
    CartographyNodeSchema,
)


@dataclass(frozen=True)
class SemgrepDeploymentProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    name: PropertyRef = PropertyRef("name", extra_index=True)
    slug: PropertyRef = PropertyRef("slug", extra_index=True)


@dataclass(frozen=True)
class SemgrepDeploymentSchema(CartographyNodeSchema):
    label: str = "SemgrepDeployment"
    properties: SemgrepDeploymentProperties = SemgrepDeploymentProperties()
