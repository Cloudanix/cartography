import pytest

from cartography.graph.querybuilder import build_create_index_queries_for_matchlink
from cartography.graph.querybuilder import build_matchlink_query
from tests.data.graph.querybuilder.sample_models.matchlink import FakeMatchLinkMissingSubResourceProps
from tests.data.graph.querybuilder.sample_models.matchlink import FakeRelWithoutSource
from tests.data.graph.querybuilder.sample_models.matchlink import FakeUserToRoleMatchLink
from tests.data.graph.querybuilder.sample_models.matchlink import FakeUserToRoleMatchLinkInward
from tests.unit.cartography.graph.helpers import remove_leading_whitespace_and_empty_lines as clean_query


class TestBuildMatchlinkQuery:
    def test_generates_expected_query(self):
        query = build_matchlink_query(FakeUserToRoleMatchLink())

        expected = """
        UNWIND $DictList as item
            MATCH (from:FakeUser{id: item.user_id})
            MATCH (to:FakeRole{name: item.role_name})
            MERGE (from)-[r:HAS_ROLE]->(to)
            ON CREATE SET r.firstseen = timestamp()
            SET
                r.lastupdated = $lastupdated,
                r._sub_resource_label = $_sub_resource_label,
                r._sub_resource_id = $_sub_resource_id
        """
        assert clean_query(query) == clean_query(expected)

    def test_inward_direction_flips_arrow(self):
        query = build_matchlink_query(FakeUserToRoleMatchLinkInward())
        assert "MERGE (from)<-[r:HAS_ROLE]-(to)" in query

    def test_missing_source_matcher_raises(self):
        with pytest.raises(ValueError, match="source node matcher"):
            build_matchlink_query(FakeRelWithoutSource())

    def test_missing_sub_resource_props_raises(self):
        with pytest.raises(ValueError, match="_sub_resource_label"):
            build_matchlink_query(FakeMatchLinkMissingSubResourceProps())


class TestBuildCreateIndexQueriesForMatchlink:
    def test_generates_source_target_and_rel_indexes(self):
        queries = build_create_index_queries_for_matchlink(FakeUserToRoleMatchLink())

        assert queries == [
            'CREATE INDEX IF NOT EXISTS FOR (n:FakeUser) ON (n.id);',
            'CREATE INDEX IF NOT EXISTS FOR (n:FakeRole) ON (n.name);',
            'CREATE INDEX IF NOT EXISTS FOR ()-[r:HAS_ROLE]-() ON (r._sub_resource_label, r._sub_resource_id);',
        ]

    def test_missing_source_matcher_returns_empty(self):
        assert build_create_index_queries_for_matchlink(FakeRelWithoutSource()) == []
