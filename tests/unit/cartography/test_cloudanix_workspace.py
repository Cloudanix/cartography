from types import SimpleNamespace
from unittest.mock import MagicMock

import cloudanix
from cartography.intel.create_indexes import get_index_statements

CONSTRAINT = (
    'CREATE CONSTRAINT cloudanix_workspace_id_unique IF NOT EXISTS '
    'FOR (w:CloudanixWorkspace) REQUIRE w.id IS UNIQUE;'
)


def test_indexes_cypher_makes_the_workspace_id_unique():
    assert CONSTRAINT in get_index_statements()


def test_indexes_cypher_has_no_plain_workspace_id_index():
    # Neo4j refuses a uniqueness constraint over a schema a plain index already covers.
    plain = [s for s in get_index_statements() if s.startswith('CREATE INDEX') and '(n:CloudanixWorkspace)' in s]
    assert plain == []


def test_sync_runs_no_schema_change():
    # regression: a DROP INDEX / CREATE CONSTRAINT from this stage waited on a long transaction for Neo4j's
    # exclusive schema lock and queued every sync behind it (US prod, 2026-11-03).
    session = MagicMock()
    config = SimpleNamespace(
        update_tag=1, params={'workspace': {'id_string': 'ws-1', 'name': 'ws', 'account_id': '1'}},
    )

    cloudanix.run(session, config)

    session.run.assert_not_called()
    session.execute_write.assert_called_once()
