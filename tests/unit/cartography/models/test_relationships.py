from dataclasses import FrozenInstanceError

import pytest

from cartography.models.core.common import PropertyRef
from cartography.models.core.relationships import make_source_node_matcher
from cartography.models.core.relationships import SourceNodeMatcher
from tests.data.graph.querybuilder.sample_models.matchlink import FakeRelWithoutSource
from tests.data.graph.querybuilder.sample_models.matchlink import FakeUserToRoleMatchLink


def test_make_source_node_matcher_exposes_property_refs():
    ref = PropertyRef('user_id')
    matcher = make_source_node_matcher({'id': ref})

    assert isinstance(matcher, SourceNodeMatcher) or type(matcher).__name__ == SourceNodeMatcher.__name__
    assert matcher.id is ref


def test_source_node_matcher_is_frozen():
    matcher = make_source_node_matcher({'id': PropertyRef('user_id')})
    with pytest.raises(FrozenInstanceError):
        matcher.id = PropertyRef('other')


def test_rel_schema_source_fields_default_to_none():
    rel = FakeRelWithoutSource()
    assert rel.source_node_label is None
    assert rel.source_node_matcher is None


def test_matchlink_schema_declares_source_fields():
    rel = FakeUserToRoleMatchLink()
    assert rel.source_node_label == 'FakeUser'
    assert rel.source_node_matcher is not None
    assert rel.source_node_matcher.id.name == 'user_id'
