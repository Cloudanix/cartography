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
class SlackBotNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    name: PropertyRef = PropertyRef("name", extra_index=True)
    real_name: PropertyRef = PropertyRef("real_name")
    deleted: PropertyRef = PropertyRef("deleted")
    is_bot: PropertyRef = PropertyRef("is_bot")
    is_app_user: PropertyRef = PropertyRef("is_app_user")


@dataclass(frozen=True)
class SlackTeamToSlackBotRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)


@dataclass(frozen=True)
# (:SlackTeam)-[:RESOURCE]->(:SlackBot)
class SlackTeamToBotRel(CartographyRelSchema):
    target_node_label: str = "SlackTeam"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {"id": PropertyRef("TEAM_ID", set_in_kwargs=True)},
    )
    direction: LinkDirection = LinkDirection.INWARD
    rel_label: str = "RESOURCE"
    properties: SlackTeamToSlackBotRelProperties = SlackTeamToSlackBotRelProperties()


@dataclass(frozen=True)
class SlackBotSchema(CartographyNodeSchema):
    label: str = "SlackBot"
    properties: SlackBotNodeProperties = SlackBotNodeProperties()
    sub_resource_relationship: SlackTeamToBotRel = SlackTeamToBotRel()
    extra_node_labels: ExtraNodeLabels = ExtraNodeLabels(
        [
            "ThirdPartyApp",
            "SlackUser",  # DEPRECATED: will be deleted in v1
        ],
    )
