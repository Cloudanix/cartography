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


@dataclass(frozen=True)
class VercelSharedEnvVarNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    key: PropertyRef = PropertyRef("key", extra_index=True)
    type: PropertyRef = PropertyRef("type")
    target: PropertyRef = PropertyRef("target")
    created_at: PropertyRef = PropertyRef("createdAt")
    updated_at: PropertyRef = PropertyRef("updatedAt")
    # NOTE: value is intentionally omitted — never store secrets


@dataclass(frozen=True)
class VercelSharedEnvVarToTeamRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
# (:VercelTeam)-[:RESOURCE]->(:VercelSharedEnvironmentVariable)
class VercelSharedEnvVarToTeamRel(CartographyRelSchema):
    target_node_label: str = "VercelTeam"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("TEAM_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: VercelSharedEnvVarToTeamRelProperties = (
        VercelSharedEnvVarToTeamRelProperties()
    )


@dataclass(frozen=True)
class VercelSharedEnvironmentVariableSchema(CartographyNodeSchema):
    label: str = "VercelSharedEnvironmentVariable"
    properties: VercelSharedEnvVarNodeProperties = VercelSharedEnvVarNodeProperties()
    sub_resource_relationship: VercelSharedEnvVarToTeamRel = (
        VercelSharedEnvVarToTeamRel()
    )
