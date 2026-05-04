from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import (
    CartographyNodeProperties,
    CartographyNodeSchema,
)


@dataclass(frozen=True)
class BigfixRootNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class BigfixRootSchema(CartographyNodeSchema):
    label: str = "BigfixRoot"
    properties: BigfixRootNodeProperties = BigfixRootNodeProperties()
