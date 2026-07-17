from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from cartography.client.core.tx import ensure_indexes
from cartography.client.core.tx import write_query_tx


def test_write_query_tx_runs_query_without_params():
    tx = MagicMock()
    write_query_tx(tx, "CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)")
    tx.run.assert_called_once_with("CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)")


@patch("cartography.client.core.tx.build_create_index_queries")
def test_ensure_indexes_uses_managed_transaction(mock_build):
    # Each generated index query must go through execute_write (managed tx, retries on
    # TransientError), not a raw auto-commit session.run.
    queries = [
        "CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Bar) ON (n.id)",
    ]
    mock_build.return_value = queries
    session = MagicMock()

    ensure_indexes(session, MagicMock())

    session.run.assert_not_called()
    assert session.execute_write.call_count == len(queries)
    for query, call in zip(queries, session.execute_write.call_args_list):
        assert call.args == (write_query_tx, query)


@patch("cartography.client.core.tx.build_create_index_queries")
def test_ensure_indexes_rejects_non_create_index_query(mock_build):
    # Guard against accidentally running an arbitrary write through this DDL helper.
    mock_build.return_value = ["MATCH (n) DETACH DELETE n"]
    session = MagicMock()

    with pytest.raises(ValueError):
        ensure_indexes(session, MagicMock())

    session.execute_write.assert_not_called()
