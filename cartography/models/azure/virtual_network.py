import logging
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

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AzureVirtualNetworkProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    name: PropertyRef = PropertyRef("name")
    location: PropertyRef = PropertyRef("location")
    provisioning_state: PropertyRef = PropertyRef("provisioning_state")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AzureVirtualNetworkToSubscriptionRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AzureVirtualNetworkToSubscriptionRel(CartographyRelSchema):
    target_node_label: str = "AzureSubscription"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("AZURE_SUBSCRIPTION_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: AzureVirtualNetworkToSubscriptionRelProperties = (
        AzureVirtualNetworkToSubscriptionRelProperties()
    )


@dataclass(frozen=True)
class AzureVirtualNetworkSchema(CartographyNodeSchema):
    label: str = "AzureVirtualNetwork"
    properties: AzureVirtualNetworkProperties = AzureVirtualNetworkProperties()
    sub_resource_relationship: AzureVirtualNetworkToSubscriptionRel = (
        AzureVirtualNetworkToSubscriptionRel()
    )
