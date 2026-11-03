import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import cloudanix
from cartography.intel.create_indexes import get_index_statements

CONSTRAINT = (
    'CREATE CONSTRAINT cloudanix_workspace_id_unique IF NOT EXISTS '
    'FOR (w:CloudanixWorkspace) REQUIRE w.id IS UNIQUE;'
)
# Any variable name, case and spacing: only the label and the id property matter.
PLAIN_WORKSPACE_ID_INDEX = re.compile(
    r'\s*CREATE\s+INDEX\b.*\(\s*(\w+)\s*:\s*CloudanixWorkspace\s*\)\s*ON\s*\(\s*\1\.id\s*\)', re.IGNORECASE,
)


def test_indexes_cypher_makes_the_workspace_id_unique():
    assert CONSTRAINT in get_index_statements()


def test_indexes_cypher_has_no_plain_workspace_id_index():
    # Neo4j refuses a uniqueness constraint over a schema a plain index already covers.
    plain = [s for s in get_index_statements() if PLAIN_WORKSPACE_ID_INDEX.match(s)]
    assert plain == []


def test_plain_workspace_id_index_pattern_ignores_variable_name_and_indent():
    assert PLAIN_WORKSPACE_ID_INDEX.match('  create index ws_id IF NOT EXISTS FOR (w : CloudanixWorkspace) ON (w.id);')
    assert not PLAIN_WORKSPACE_ID_INDEX.match('CREATE INDEX IF NOT EXISTS FOR (n:CloudanixWorkspace) ON (n.name);')
    assert not PLAIN_WORKSPACE_ID_INDEX.match(CONSTRAINT)


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
