import logging
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

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AzureNetworkSecurityGroupProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    name: PropertyRef = PropertyRef("name")
    location: PropertyRef = PropertyRef("location")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AzureNetworkSecurityGroupToSubscriptionRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AzureNetworkSecurityGroupToSubscriptionRel(CartographyRelSchema):
    target_node_label: str = "AzureSubscription"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("AZURE_SUBSCRIPTION_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: AzureNetworkSecurityGroupToSubscriptionRelProperties = (
        AzureNetworkSecurityGroupToSubscriptionRelProperties()
    )


@dataclass(frozen=True)
class AzureNetworkSecurityGroupSchema(CartographyNodeSchema):
    label: str = "AzureNetworkSecurityGroup"
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(["NetworkAccessControl"])
    properties: AzureNetworkSecurityGroupProperties = (
        AzureNetworkSecurityGroupProperties()
    )
    sub_resource_relationship: AzureNetworkSecurityGroupToSubscriptionRel = (
        AzureNetworkSecurityGroupToSubscriptionRel()
    )
