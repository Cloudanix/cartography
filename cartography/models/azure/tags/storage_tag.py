from dataclasses import dataclass

from cartography.models.azure.tags.tag import (
    AzureTagProperties,
    AzureTagToSubscriptionRel,
)
from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import CartographyNodeSchema
from cartography.models.core.relationships import (
    CartographyRelProperties,
    CartographyRelSchema,
    LinkDirection,
    OtherRelationships,
    TargetNodeMatcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class StorageAccountToTagRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class StorageAccountToTagRel(CartographyRelSchema):
    target_node_label: str = "AzureStorageAccount"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("resource_id")},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "TAGGED"
    properties: StorageAccountToTagRelProperties = StorageAccountToTagRelProperties()


@dataclass(frozen=True)
class AzureStorageTagsSchema(CartographyNodeSchema):
    label: str = "AzureTag"
    properties: AzureTagProperties = AzureTagProperties()
    sub_resource_relationship: AzureTagToSubscriptionRel = AzureTagToSubscriptionRel()
    other_relationships: OtherRelationships = OtherRelationships(
        [
            StorageAccountToTagRel(),
        ],
    )
