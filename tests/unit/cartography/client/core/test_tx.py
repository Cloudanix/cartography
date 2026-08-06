from unittest.mock import MagicMock
from unittest.mock import patch

import pytest

from cartography.client.core.tx import ensure_indexes
from cartography.client.core.tx import load
from cartography.client.core.tx import load_graph_data
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


@patch("cartography.client.core.tx.build_ingestion_query")
@patch("cartography.client.core.tx.ensure_indexes")
def test_load_empty_list_short_circuits(mock_ensure, mock_build):
    # No data -> no index creation, no query build, no writes.
    session = MagicMock()

    load(session, MagicMock(), [])

    mock_ensure.assert_not_called()
    mock_build.assert_not_called()
    session.execute_write.assert_not_called()


@patch("cartography.client.core.tx.build_ingestion_query")
@patch("cartography.client.core.tx.ensure_indexes")
def test_load_nonempty_list_loads(mock_ensure, mock_build):
    session = MagicMock()
    mock_build.return_value = "UNWIND $DictList AS item MERGE (n:Foo{id: item.id})"

    load(session, MagicMock(), [{"id": 1}])

    mock_ensure.assert_called_once()
    assert session.execute_write.call_count == 1


def test_load_graph_data_batches_at_batch_size():
    session = MagicMock()
    data = [{"id": i} for i in range(25)]

    load_graph_data(session, "UNWIND $DictList AS item RETURN item", data, batch_size=10)

    assert session.execute_write.call_count == 3  # 10 + 10 + 5
    batch_sizes = [len(call.kwargs["DictList"]) for call in session.execute_write.call_args_list]
    assert batch_sizes == [10, 10, 5]


def test_load_graph_data_default_batch_size_is_10000():
    session = MagicMock()
    data = [{"id": i} for i in range(10001)]

    load_graph_data(session, "UNWIND $DictList AS item RETURN item", data)

    assert session.execute_write.call_count == 2


@pytest.mark.parametrize("bad_size", [0, -1])
def test_load_graph_data_rejects_nonpositive_batch_size(bad_size):
    with pytest.raises(ValueError):
        load_graph_data(MagicMock(), "q", [{"id": 1}], batch_size=bad_size)


@pytest.mark.parametrize("bad_size", [0, -1])
def test_load_rejects_nonpositive_batch_size(bad_size):
    with pytest.raises(ValueError):
        load(MagicMock(), MagicMock(), [{"id": 1}], batch_size=bad_size)


@patch("cartography.client.core.tx.load_graph_data")
@patch("cartography.client.core.tx.build_ingestion_query")
@patch("cartography.client.core.tx.ensure_indexes")
def test_load_passes_batch_size_through(mock_ensure, mock_build, mock_lgd):
    session = MagicMock()
    data = [{"id": 1}]

    load(session, MagicMock(), data, batch_size=42, lastupdated=1)

    mock_lgd.assert_called_once_with(session, mock_build.return_value, data, batch_size=42, lastupdated=1)
