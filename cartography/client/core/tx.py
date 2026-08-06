import logging
import time
from functools import partial
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TypeVar
from typing import Union

import backoff
import neo4j
import neo4j.exceptions

from cartography.graph.querybuilder import build_create_index_queries
from cartography.graph.querybuilder import build_ingestion_query
from cartography.models.core.nodes import CartographyNodeSchema
from cartography.util import backoff_handler
from cartography.util import batch

logger = logging.getLogger(__name__)

T = TypeVar("T")

# Rows per write transaction. Matches upstream cartography's default; tune per call
# via the batch_size param if a module's rows are unusually wide.
DEFAULT_LOAD_BATCH_SIZE = 10000

_MAX_NETWORK_RETRIES = 5
_MAX_ENTITY_NOT_FOUND_RETRIES = 5
_MAX_BUFFER_ERROR_RETRIES = 5
_NETWORK_EXCEPTIONS: tuple = (
    ConnectionResetError,
    neo4j.exceptions.ServiceUnavailable,
    neo4j.exceptions.SessionExpired,
    neo4j.exceptions.TransientError,
)


def _is_retryable_client_error(exc: Exception) -> bool:
    """
    EntityNotFound during concurrent write operations is a known transient Neo4j error:
    with concurrent MERGE/DELETE one thread can delete an entity another thread has
    referenced but not yet locked. Neo4j maintainers recommend retrying it even though
    the driver classifies it as a non-retryable ClientError
    (https://github.com/neo4j/neo4j/issues/6823). This is exactly the condition created
    by our 8-worker-per-provider write concurrency.
    """
    if not isinstance(exc, neo4j.exceptions.ClientError):
        return False
    # exc.code can be None for locally-created errors
    return exc.code == "Neo.ClientError.Statement.EntityNotFound"


def _is_retryable_buffer_error(exc: Exception) -> bool:
    """
    BufferError("... cannot be re-sized") is a known transient error from the neo4j
    driver's internal buffer management under multi-threaded use.
    """
    return isinstance(exc, BufferError) and "cannot be re-sized" in str(exc)


def _run_with_retry(operation: Callable[[], T], target: str) -> T:
    """
    Execute the supplied callable with retry + exponential backoff for transient network
    errors, EntityNotFound ClientErrors, and re-size BufferErrors. Anything else raises
    immediately; exhausted retries re-raise the last error.
    """
    network_attempts = 0
    entity_attempts = 0
    buffer_attempts = 0
    network_wait = backoff.expo()
    entity_wait = backoff.expo()
    buffer_wait = backoff.expo()

    def _backoff(kind: str, attempts: int, max_attempts: int, wait_gen: Any, exc: Exception) -> None:
        wait = next(wait_gen) or 1.0
        backoff_handler({"wait": wait, "tries": attempts, "target": target, "exception": exc})
        logger.warning(f"{kind} retry {attempts}/{max_attempts} for {target}: {exc}")
        time.sleep(wait)

    while True:
        try:
            result = operation()
            recovered = network_attempts + entity_attempts + buffer_attempts
            if recovered:
                logger.info(f"Recovered after {recovered} retries. Function: {target}")
            return result
        except _NETWORK_EXCEPTIONS as exc:
            if network_attempts >= _MAX_NETWORK_RETRIES - 1:
                raise
            network_attempts += 1
            _backoff("Network error", network_attempts, _MAX_NETWORK_RETRIES, network_wait, exc)
        except neo4j.exceptions.ClientError as exc:
            if not _is_retryable_client_error(exc) or entity_attempts >= _MAX_ENTITY_NOT_FOUND_RETRIES - 1:
                raise
            entity_attempts += 1
            _backoff("EntityNotFound", entity_attempts, _MAX_ENTITY_NOT_FOUND_RETRIES, entity_wait, exc)
        except BufferError as exc:
            if not _is_retryable_buffer_error(exc) or buffer_attempts >= _MAX_BUFFER_ERROR_RETRIES - 1:
                raise
            buffer_attempts += 1
            _backoff("BufferError", buffer_attempts, _MAX_BUFFER_ERROR_RETRIES, buffer_wait, exc)


def execute_write_with_retry(
        neo4j_session: neo4j.Session,
        tx_func: Any,
        *args: Any,
        **kwargs: Any,
) -> Any:
    """
    Run a transaction function through session.execute_write with _run_with_retry's
    transient-error classification on top of the driver's own TransientError handling.
    Use for any custom write that does not fit the load_graph_data() path.
    """
    target = getattr(tx_func, "__qualname__", repr(tx_func))
    operation = partial(neo4j_session.execute_write, tx_func, *args, **kwargs)
    return _run_with_retry(operation, target)


def run_write_query(neo4j_session: neo4j.Session, query: str, **parameters: Any) -> None:
    """
    Execute a single write query inside a managed transaction with retry. Drop-in
    replacement for raw auto-commit neo4j_session.run(query, ...) in intel modules
    (perf plan Phase 3.7).
    """
    def _run_query_tx(tx: neo4j.Transaction) -> None:
        tx.run(query, **parameters).consume()

    def _operation() -> None:
        neo4j_session.execute_write(_run_query_tx)

    _run_with_retry(_operation, "run_write_query")


def read_list_of_values_tx(tx: neo4j.Transaction, query: str, **kwargs) -> List[Union[str, int]]:
    """
    Runs the given Neo4j query in the given transaction object and returns a list of either str or int. This is intended
    to be run only with queries that return a list of a single field.

    Example usage:
        query = "MATCH (a:TestNode) RETURN a.name ORDER BY a.name"

        values = neo4j_session.execute_read(read_list_of_values_tx, query)

    :param tx: A neo4j read transaction object
    :param query: A neo4j query string that returns a list of single values. For example,
        `MATCH (a:TestNode) RETURN a.name ORDER BY a.name` is intended to work, but
        `MATCH (a:TestNode) RETURN a.name ORDER BY a.name, a.age, a.x, a.y, a.z` is not.
        If the query happens to return a list of complex objects with more than one field, then only the value of the
        first field of each item in the list will be returned. This is not a supported scenario for this function though
        so please ensure that the `query` does return a list of single values.
    :param kwargs: kwargs that are passed to tx.run()'s kwargs argument.
    :return: A list of str or int.
    """
    result: neo4j.BoltStatementResult = tx.run(query, kwargs)
    values = [n.value() for n in result]
    result.consume()
    return values


def read_single_value_tx(tx: neo4j.Transaction, query: str, **kwargs) -> Optional[Union[str, int]]:
    """
    Runs the given Neo4j query in the given transaction object and returns a str, int, or None. This is intended to be
    run only with queries that return a single str, int, or None value.

    Example usage:
        query = '''MATCH (a:TestNode{name: "Lisa"}) RETURN a.age'''  # Ensure that we are querying just one node!

        value = neo4j_session.execute_read(read_single_value_tx, query)

    :param tx: A neo4j read transaction object
    :param query: A neo4j query string that returns a single value. For example,
        `MATCH (a:TestNode{name: "Lisa"}) RETURN a.age` is intended to work (assuming that there is only one `TestNode`
         where `name=Lisa`), but
        `MATCH (a:TestNode) RETURN a.age ORDER BY a.age` is not (assuming that there is more than one `TestNode` in the
        graph. If the query happens to match more than one value, only the first one will be returned. If the query
        happens to return a dictionary or complex object, this scenario is not supported and can result in unpredictable
        behavior. Be careful in selecting the query.
        To return more complex objects, see the "*dict*" or the "*tuple*" functions in this library.
    :param kwargs: kwargs that are passed to tx.run()'s kwargs argument.
    :return: The result of the query as a single str, int, or None
    """
    result: neo4j.BoltStatementResult = tx.run(query, kwargs)
    record: neo4j.Record = result.single()

    value = record.value() if record else None

    result.consume()
    return value


def read_list_of_dicts_tx(tx: neo4j.Transaction, query: str, **kwargs) -> List[Dict[str, Any]]:
    """
    Runs the given Neo4j query in the given transaction object and returns the results as a list of dicts.

    Example usage:
        query = "MATCH (a:TestNode) RETURN a.name AS name, a.age AS age ORDER BY age"

        data = neo4j_session.execute_read(read_list_of_dicts_tx, query)

        # expected returned data shape -> data = [{'name': 'Lisa', 'age': 8}, {'name': 'Homer', 'age': 39}]

    :param tx: A neo4j read transaction object
    :param query: A neo4j query string that returns one or more values.
    :param kwargs: kwargs that are passed to tx.run()'s kwargs argument.
    :return: The result of the query as a list of dicts.
    """
    result: neo4j.BoltStatementResult = tx.run(query, kwargs)
    values = [n.data() for n in result]
    result.consume()
    return values


def read_list_of_tuples_tx(tx: neo4j.Transaction, query: str, **kwargs) -> List[Tuple[Any, ...]]:
    """
    Runs the given Neo4j query in the given transaction object and returns the results as a list of tuples.

    Example usage:
        ```
        query = "MATCH (a:TestNode) RETURN a.name AS name, a.age AS age ORDER BY age"

        simpsons_characters = neo4j_session.execute_read(read_list_of_tuples_tx, query)

        # expected returned data shape -> simpsons_characters = [('Lisa', 8), ('Homer', 39)]

        # The advantage of this function over `read_list_of_dicts_tx()` is that you can now run things like this:

        for name, age in simpsons_characters:
            print(name, age)
        ```

    :param tx: A neo4j read transaction object
    :param query: A neo4j query string that returns one or more values.
    :param kwargs: kwargs that are passed to tx.run()'s kwargs argument.
    :return: The result of the query as a list of tuples.
    """
    result: neo4j.BoltStatementResult = tx.run(query, kwargs)
    values: List[Any] = result.values()
    result.consume()
    # All neo4j APIs return List type- https://neo4j.com/docs/api/python-driver/current/api.html#result - so we do this:
    return [tuple(val) for val in values]


def read_single_dict_tx(tx: neo4j.Transaction, query: str, **kwargs) -> Dict[str, Any]:
    """
    Runs the given Neo4j query in the given transaction object and returns the single dict result. This is intended to
    be run only with queries that return a single dict.

    Example usage:
        query = '''MATCH (a:TestNode{name: "Homer"}) RETURN a.name AS name, a.age AS age'''
        result = neo4j_session.execute_read(read_single_dict_tx, query)

        # expected returned data shape -> result = {'name': 'Lisa', 'age': 8}

    :param tx: A neo4j read transaction object
    :param query: A neo4j query string that returns a single dict. For example,
        `MATCH (a:TestNode{name: "Lisa"}) RETURN a.age, a.name` is intended to work (assuming that there is only one
        `TestNode` where `name=Lisa`), but
        `MATCH (a:TestNode) RETURN a.age ORDER BY a.age, a.name` is not (assuming that there is more than one `TestNode`
        in the graph. If the query happens to match more than one node, only the first one will be returned.
        If the query happens to return more than one dict, only the first dict will be returned however
        `read_list_of_dicts_tx()` is better suited for this use-case.
    :param kwargs: kwargs that are passed to tx.run()'s kwargs argument.
    :return: The result of the query as a single dict.
    """
    result: neo4j.BoltStatementResult = tx.run(query, kwargs)
    record: neo4j.Record = result.single()

    value = record.data() if record else None

    result.consume()
    return value


def write_list_of_dicts_tx(
        tx: neo4j.Transaction,
        query: str,
        **kwargs,
) -> None:
    """
    Writes a list of dicts to Neo4j.

    Example usage:
        import neo4j
        dict_list: List[Dict[Any, Any]] = [{...}, ...]

        neo4j_driver = neo4j.driver(... args ...)
        neo4j_session = neo4j_driver.Session(... args ...)

        neo4j_session.execute_write(
            write_list_of_dicts_tx,
            '''
            UNWIND $DictList as data
                MERGE (a:SomeNode{id: data.id})
                SET
                    a.other_field = $other_field,
                    a.yet_another_kwarg_field = $yet_another_kwarg_field
                ...
            ''',
            DictList=dict_list,
            other_field='some extra value',
            yet_another_kwarg_field=1234
        )

    :param tx: The neo4j write transaction.
    :param query: The Neo4j write query to run.
    :param kwargs: Keyword args to be supplied to the Neo4j query.
    :return: None
    """
    tx.run(query, kwargs).consume()


def write_query_tx(
        tx: neo4j.Transaction,
        query: str,
) -> None:
    """
    Runs a single parameter-less write query inside a managed transaction. Used for DDL such as
    `CREATE INDEX` where there is no `$DictList` payload.
    :param tx: The neo4j write transaction.
    :param query: The Neo4j write query to run.
    :return: None
    """
    tx.run(query)


def load_graph_data(
        neo4j_session: neo4j.Session,
        query: str,
        dict_list: List[Dict[str, Any]],
        batch_size: int = DEFAULT_LOAD_BATCH_SIZE,
        **kwargs,
) -> None:
    """
    Writes data to the graph.
    :param neo4j_session: The Neo4j session
    :param query: The Neo4j write query to run. This query is not meant to be handwritten, rather it should be generated
    with cartography.graph.querybuilder.build_ingestion_query().
    :param dict_list: The data to load to the graph represented as a list of dicts.
    :param batch_size: Number of items to write per transaction. Defaults to DEFAULT_LOAD_BATCH_SIZE.
    :param kwargs: Allows additional keyword args to be supplied to the Neo4j query.
    :return: None
    """
    if batch_size <= 0:
        raise ValueError(f"batch_size must be greater than 0, got {batch_size}")
    for data_batch in batch(dict_list, size=batch_size):
        execute_write_with_retry(
            neo4j_session,
            write_list_of_dicts_tx,
            query,
            DictList=data_batch,
            **kwargs,
        )


def ensure_indexes(neo4j_session: neo4j.Session, node_schema: CartographyNodeSchema) -> None:
    """
    Creates indexes if they don't exist for the given CartographyNodeSchema object, as well as for all of the
    relationships defined on its `other_relationships` and `sub_resource_relationship` fields. This operation is
    idempotent.

    This ensures that every time we need to MATCH on a node to draw a relationship to it, the field used for the MATCH
    will be indexed, making the operation fast.
    :param neo4j_session: The neo4j session
    :param node_schema: The node_schema object to create indexes for.
    """
    queries = build_create_index_queries(node_schema)

    for query in queries:
        if not query.startswith('CREATE INDEX IF NOT EXISTS'):
            raise ValueError('Query provided to `ensure_indexes()` does not start with "CREATE INDEX IF NOT EXISTS".')
        # Managed transaction so index creation retries on TransientError instead of failing the sync.
        neo4j_session.execute_write(write_query_tx, query)


def load(
        neo4j_session: neo4j.Session,
        node_schema: CartographyNodeSchema,
        dict_list: List[Dict[str, Any]],
        batch_size: int = DEFAULT_LOAD_BATCH_SIZE,
        **kwargs,
) -> None:
    """
    Main entrypoint for intel modules to write data to the graph. Ensures that indexes exist for the datatypes loaded
    to the graph and then performs the load operation.
    :param neo4j_session: The Neo4j session
    :param node_schema: The CartographyNodeSchema object to create indexes for and generate a query.
    :param dict_list: The data to load to the graph represented as a list of dicts.
    :param batch_size: Number of items to write per transaction. Defaults to DEFAULT_LOAD_BATCH_SIZE.
    :param kwargs: Allows additional keyword args to be supplied to the Neo4j query.
    :return: None
    """
    if batch_size <= 0:
        raise ValueError(f"batch_size must be greater than 0, got {batch_size}")
    if len(dict_list) == 0:
        # Nothing to load; skip index creation and query generation round-trips.
        return
    ensure_indexes(neo4j_session, node_schema)
    ingestion_query = build_ingestion_query(node_schema)
    load_graph_data(neo4j_session, ingestion_query, dict_list, batch_size=batch_size, **kwargs)
