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
class DuoTokenNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("token_id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    admins: PropertyRef = PropertyRef("admins")
    serial: PropertyRef = PropertyRef("serial", extra_index=True)
    token_id: PropertyRef = PropertyRef("token_id", extra_index=True)
    totp_step: PropertyRef = PropertyRef("totp_step")
    type: PropertyRef = PropertyRef("type")


@dataclass(frozen=True)
class DuoTokenToDuoApiHostRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class DuoTokenToDuoApiHostRel(CartographyRelSchema):
    target_node_label: str = "DuoApiHost"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("DUO_API_HOSTNAME", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: DuoTokenToDuoApiHostRelProperties = DuoTokenToDuoApiHostRelProperties()


class DuoTokenToDuoUserRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
class DuoTokenToDuoUserRel(CartographyRelSchema):
    target_node_label: str = "DuoUser"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"user_id": PropertyRef("user_id")},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "HAS_DUO_TOKEN"
    properties: DuoTokenToDuoUserRelProperties = DuoTokenToDuoUserRelProperties()


@dataclass(frozen=True)
class DuoTokenSchema(CartographyNodeSchema):
    label: str = "DuoToken"
    properties: DuoTokenNodeProperties = DuoTokenNodeProperties()
    sub_resource_relationship: DuoTokenToDuoApiHostRel = DuoTokenToDuoApiHostRel()
    other_relationships: OtherRelationships = OtherRelationships(
        rels=[
            DuoTokenToDuoUserRel(),
        ],
    )
