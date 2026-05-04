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
    OtherRelationships,
    TargetNodeMatcher,
    make_target_node_matcher,
)


@dataclass(frozen=True)
class GCPCloudSQLAuthorizedNetworkProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    name: PropertyRef = PropertyRef("name")
    value: PropertyRef = PropertyRef("value")
    expiration_time: PropertyRef = PropertyRef("expiration_time")
    instance_id: PropertyRef = PropertyRef("instance_id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AuthorizedNetworkToProjectRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AuthorizedNetworkToProjectRel(CartographyRelSchema):
    target_node_label: str = "GCPProject"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("PROJECT_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: AuthorizedNetworkToProjectRelProperties = (
        AuthorizedNetworkToProjectRelProperties()
    )


@dataclass(frozen=True)
class AuthorizedNetworkToSqlInstanceRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class AuthorizedNetworkToSqlInstanceRel(CartographyRelSchema):
    target_node_label: str = "GCPCloudSQLInstance"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("instance_id")},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "AUTHORIZED_NETWORK"
    properties: AuthorizedNetworkToSqlInstanceRelProperties = (
        AuthorizedNetworkToSqlInstanceRelProperties()
    )


@dataclass(frozen=True)
class GCPCloudSQLAuthorizedNetworkSchema(CartographyNodeSchema):
    label: str = "GCPCloudSQLAuthorizedNetwork"
    properties: GCPCloudSQLAuthorizedNetworkProperties = (
        GCPCloudSQLAuthorizedNetworkProperties()
    )
    sub_resource_relationship: AuthorizedNetworkToProjectRel = (
        AuthorizedNetworkToProjectRel()
    )
    other_relationships: OtherRelationships = OtherRelationships(
        [
            AuthorizedNetworkToSqlInstanceRel(),
        ],
    )
