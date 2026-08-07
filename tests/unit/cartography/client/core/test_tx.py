from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from neo4j.exceptions import ClientError
from neo4j.exceptions import ServiceUnavailable
from neo4j.exceptions import TransientError

from cartography.client.core.tx import _is_retryable_buffer_error
from cartography.client.core.tx import _is_retryable_client_error
from cartography.client.core.tx import _run_with_retry
from cartography.client.core.tx import ensure_indexes
from cartography.client.core.tx import execute_write_with_retry
from cartography.client.core.tx import load
from cartography.client.core.tx import load_graph_data
from cartography.client.core.tx import load_matchlinks
from cartography.client.core.tx import reset_ensured_indexes_cache
from cartography.client.core.tx import run_write_query
from cartography.client.core.tx import write_query_tx
from tests.data.graph.querybuilder.sample_models.matchlink import FakeUserToRoleMatchLink


@pytest.fixture(autouse=True)
def _reset_index_cache():
    # ensure_indexes memoizes per schema class per process; isolate tests from each other.
    reset_ensured_indexes_cache()
    yield
    reset_ensured_indexes_cache()


def entity_not_found_error():
    err = ClientError("entity gone")
    err.code = "Neo.ClientError.Statement.EntityNotFound"
    return err


class FakeSchemaA:
    pass


class FakeSchemaB:
    pass


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


@patch("cartography.client.core.tx.build_create_index_queries")
def test_ensure_indexes_ignores_parallel_index_creation_race(mock_build):
    # Two workers hitting CREATE INDEX IF NOT EXISTS concurrently can still race in
    # Neo4j; the resulting EquivalentSchemaRuleAlreadyExists is the desired end state.
    mock_build.return_value = [
        "CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)",
        "CREATE INDEX IF NOT EXISTS FOR (n:Bar) ON (n.id)",
    ]
    race = ClientError("already exists")
    race.code = "Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists"
    session = MagicMock()
    session.execute_write.side_effect = [race, None]

    ensure_indexes(session, MagicMock())  # must not raise

    assert session.execute_write.call_count == 2


@patch("cartography.client.core.tx.build_create_index_queries")
def test_ensure_indexes_raises_other_client_errors(mock_build):
    mock_build.return_value = ["CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)"]
    err = ClientError("denied")
    err.code = "Neo.ClientError.Security.Forbidden"
    session = MagicMock()
    session.execute_write.side_effect = err

    with pytest.raises(ClientError):
        ensure_indexes(session, MagicMock())


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


class TestRetryClassification:
    def test_entity_not_found_is_retryable(self):
        assert _is_retryable_client_error(entity_not_found_error())

    def test_other_client_error_is_not_retryable(self):
        err = ClientError("bad")
        err.code = "Neo.ClientError.Statement.SyntaxError"
        assert not _is_retryable_client_error(err)

    def test_client_error_without_code_is_not_retryable(self):
        assert not _is_retryable_client_error(ClientError("local"))

    def test_non_client_error_is_not_retryable(self):
        assert not _is_retryable_client_error(ValueError("nope"))

    def test_resize_buffer_error_is_retryable(self):
        assert _is_retryable_buffer_error(BufferError("Existing exports of data: object cannot be re-sized"))

    def test_other_buffer_error_is_not_retryable(self):
        assert not _is_retryable_buffer_error(BufferError("something else"))


@patch("cartography.client.core.tx.time.sleep")
class TestRunWithRetry:
    def test_success_passthrough(self, mock_sleep):
        op = MagicMock(return_value="ok")
        assert _run_with_retry(op, "t") == "ok"
        mock_sleep.assert_not_called()

    def test_network_error_retried_then_succeeds(self, mock_sleep):
        op = MagicMock(side_effect=[ServiceUnavailable("down"), TransientError("busy"), "ok"])
        assert _run_with_retry(op, "t") == "ok"
        assert op.call_count == 3

    def test_network_error_exhaustion_raises(self, mock_sleep):
        op = MagicMock(side_effect=ServiceUnavailable("down"))
        with pytest.raises(ServiceUnavailable):
            _run_with_retry(op, "t")
        assert op.call_count == 5  # _MAX_NETWORK_RETRIES

    def test_entity_not_found_retried_then_succeeds(self, mock_sleep):
        op = MagicMock(side_effect=[entity_not_found_error(), "ok"])
        assert _run_with_retry(op, "t") == "ok"
        assert op.call_count == 2

    def test_non_retryable_client_error_raises_immediately(self, mock_sleep):
        err = ClientError("bad")
        err.code = "Neo.ClientError.Statement.SyntaxError"
        op = MagicMock(side_effect=err)
        with pytest.raises(ClientError):
            _run_with_retry(op, "t")
        assert op.call_count == 1

    def test_buffer_error_retried_then_succeeds(self, mock_sleep):
        op = MagicMock(side_effect=[BufferError("x cannot be re-sized"), "ok"])
        assert _run_with_retry(op, "t") == "ok"
        assert op.call_count == 2

    def test_unrelated_exception_raises_immediately(self, mock_sleep):
        op = MagicMock(side_effect=KeyError("boom"))
        with pytest.raises(KeyError):
            _run_with_retry(op, "t")
        assert op.call_count == 1


class TestExecuteWriteWithRetry:
    def test_passes_through_to_execute_write(self):
        session = MagicMock()
        tx_func = MagicMock()

        result = execute_write_with_retry(session, tx_func, "a", k=1)

        assert result is session.execute_write.return_value
        session.execute_write.assert_called_once_with(tx_func, "a", k=1)

    @patch("cartography.client.core.tx.time.sleep")
    def test_retries_entity_not_found(self, mock_sleep):
        session = MagicMock()
        session.execute_write.side_effect = [entity_not_found_error(), "ok"]

        assert execute_write_with_retry(session, MagicMock()) == "ok"
        assert session.execute_write.call_count == 2


class TestRunWriteQuery:
    def test_runs_query_in_managed_tx(self):
        session = MagicMock()

        run_write_query(session, "MERGE (n:Foo{id: $id})", id=1)

        session.execute_write.assert_called_once()
        # Execute the captured tx function against a mock transaction and verify the
        # query goes through tx.run with the given parameters.
        tx_fn = session.execute_write.call_args.args[0]
        tx = MagicMock()
        tx_fn(tx)
        tx.run.assert_called_once_with("MERGE (n:Foo{id: $id})", id=1)


@patch("cartography.client.core.tx.time.sleep")
def test_load_graph_data_retries_transient_batch_failure(mock_sleep):
    session = MagicMock()
    session.execute_write.side_effect = [entity_not_found_error(), None]

    load_graph_data(session, "UNWIND $DictList AS item RETURN item", [{"id": 1}])

    assert session.execute_write.call_count == 2


class TestEnsureIndexesMemoization:
    @patch("cartography.client.core.tx.build_create_index_queries")
    def test_second_call_for_same_schema_class_is_skipped(self, mock_build):
        mock_build.return_value = ["CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)"]
        session = MagicMock()

        ensure_indexes(session, FakeSchemaA())
        ensure_indexes(session, FakeSchemaA())

        mock_build.assert_called_once()
        assert session.execute_write.call_count == 1

    @patch("cartography.client.core.tx.build_create_index_queries")
    def test_different_schema_classes_each_run(self, mock_build):
        mock_build.return_value = ["CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)"]
        session = MagicMock()

        ensure_indexes(session, FakeSchemaA())
        ensure_indexes(session, FakeSchemaB())

        assert mock_build.call_count == 2
        assert session.execute_write.call_count == 2

    @patch("cartography.client.core.tx.build_create_index_queries")
    def test_failed_run_is_not_memoized(self, mock_build):
        mock_build.return_value = ["CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)"]
        session = MagicMock()
        err = ClientError("denied")
        err.code = "Neo.ClientError.Security.Forbidden"
        session.execute_write.side_effect = [err, None]

        with pytest.raises(ClientError):
            ensure_indexes(session, FakeSchemaA())
        ensure_indexes(session, FakeSchemaA())  # retried, succeeds this time

        assert session.execute_write.call_count == 2

    @patch("cartography.client.core.tx.build_create_index_queries")
    def test_reset_clears_memoization(self, mock_build):
        mock_build.return_value = ["CREATE INDEX IF NOT EXISTS FOR (n:Foo) ON (n.id)"]
        session = MagicMock()

        ensure_indexes(session, FakeSchemaA())
        reset_ensured_indexes_cache()
        ensure_indexes(session, FakeSchemaA())

        assert session.execute_write.call_count == 2


class TestLoadMatchlinks:
    def test_empty_list_short_circuits(self):
        session = MagicMock()

        load_matchlinks(session, FakeUserToRoleMatchLink(), [])

        session.execute_write.assert_not_called()

    def test_missing_sub_resource_kwargs_raise(self):
        with pytest.raises(ValueError, match="_sub_resource_label"):
            load_matchlinks(MagicMock(), FakeUserToRoleMatchLink(), [{"user_id": 1}])
        with pytest.raises(ValueError, match="_sub_resource_id"):
            load_matchlinks(
                MagicMock(), FakeUserToRoleMatchLink(), [{"user_id": 1}],
                _sub_resource_label="AWSAccount",
            )

    @pytest.mark.parametrize("bad_size", [0, -1])
    def test_rejects_nonpositive_batch_size(self, bad_size):
        with pytest.raises(ValueError):
            load_matchlinks(
                MagicMock(), FakeUserToRoleMatchLink(), [{"user_id": 1}], batch_size=bad_size,
                _sub_resource_label="AWSAccount", _sub_resource_id="1234",
            )

    def test_ensures_indexes_and_writes_links(self):
        session = MagicMock()
        links = [{"user_id": 1, "role_name": "admin"}]

        load_matchlinks(
            session, FakeUserToRoleMatchLink(), links,
            lastupdated=1, _sub_resource_label="AWSAccount", _sub_resource_id="1234",
        )

        # 3 index queries (source, target, rel composite) + 1 batched link write.
        assert session.execute_write.call_count == 4
        write_call = session.execute_write.call_args_list[-1]
        assert write_call.kwargs["DictList"] == links
        assert write_call.kwargs["_sub_resource_label"] == "AWSAccount"
        assert write_call.kwargs["_sub_resource_id"] == "1234"
        query = write_call.args[1]
        assert "MERGE (from)-[r:HAS_ROLE]->(to)" in query
