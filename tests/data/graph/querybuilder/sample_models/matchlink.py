from dataclasses import dataclass

from cartography.models.core.common import PropertyRef
from cartography.models.core.relationships import CartographyRelProperties
from cartography.models.core.relationships import CartographyRelSchema
from cartography.models.core.relationships import LinkDirection
from cartography.models.core.relationships import make_source_node_matcher
from cartography.models.core.relationships import make_target_node_matcher
from cartography.models.core.relationships import SourceNodeMatcher
from cartography.models.core.relationships import TargetNodeMatcher


# Test model for load_matchlinks(): (:FakeUser)-[:HAS_ROLE]->(:FakeRole) where both
# nodes already exist in the graph.
@dataclass(frozen=True)
class FakeUserToRoleRelProps(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)
    _sub_resource_label: PropertyRef = PropertyRef('_sub_resource_label', set_in_kwargs=True)
    _sub_resource_id: PropertyRef = PropertyRef('_sub_resource_id', set_in_kwargs=True)


@dataclass(frozen=True)
class FakeUserToRoleMatchLink(CartographyRelSchema):
    source_node_label: str = 'FakeUser'
    source_node_matcher: SourceNodeMatcher = make_source_node_matcher(
        {'id': PropertyRef('user_id')},
    )
    target_node_label: str = 'FakeRole'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'name': PropertyRef('role_name')},
    )
    rel_label: str = 'HAS_ROLE'
    direction: LinkDirection = LinkDirection.OUTWARD
    properties: FakeUserToRoleRelProps = FakeUserToRoleRelProps()


# Same link but INWARD: (:FakeUser)<-[:HAS_ROLE]-(:FakeRole)
@dataclass(frozen=True)
class FakeUserToRoleMatchLinkInward(FakeUserToRoleMatchLink):
    direction: LinkDirection = LinkDirection.INWARD


# Missing source_node_matcher/source_node_label: valid as a nested rel schema but
# invalid for load_matchlinks().
@dataclass(frozen=True)
class FakeRelWithoutSource(CartographyRelSchema):
    target_node_label: str = 'FakeRole'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'name': PropertyRef('role_name')},
    )
    rel_label: str = 'HAS_ROLE'
    direction: LinkDirection = LinkDirection.OUTWARD
    properties: FakeUserToRoleRelProps = FakeUserToRoleRelProps()


# Has a source matcher but lacks the _sub_resource_* rel properties required for
# matchlink cleanup scoping.
@dataclass(frozen=True)
class FakeRelPropsNoSubResource(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef('lastupdated', set_in_kwargs=True)


@dataclass(frozen=True)
class FakeMatchLinkMissingSubResourceProps(CartographyRelSchema):
    source_node_label: str = 'FakeUser'
    source_node_matcher: SourceNodeMatcher = make_source_node_matcher(
        {'id': PropertyRef('user_id')},
    )
    target_node_label: str = 'FakeRole'
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher(
        {'name': PropertyRef('role_name')},
    )
    rel_label: str = 'HAS_ROLE'
    direction: LinkDirection = LinkDirection.INWARD
    properties: FakeRelPropsNoSubResource = FakeRelPropsNoSubResource()
