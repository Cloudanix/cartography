from tests.integration.cartography.graph.plan_guard import collect_operator_types
from tests.integration.cartography.graph.plan_guard import find_banned_operators
from tests.integration.cartography.graph.plan_guard import iter_generated_queries

# A plan tree shaped like neo4j.ResultSummary.plan: nested dicts with operatorType + children.
BAD_PLAN = {
    "operatorType": "ProduceResults",
    "children": [
        {
            "operatorType": "Filter",
            "children": [
                {"operatorType": "AllNodesScan@neo4j", "children": []},
            ],
        },
    ],
}

GOOD_PLAN = {
    "operatorType": "ProduceResults",
    "children": [
        {
            "operatorType": "Expand(All)",
            "children": [
                {"operatorType": "NodeUniqueIndexSeek", "children": []},
            ],
        },
    ],
}


def test_collect_operator_types_walks_tree():
    assert collect_operator_types(BAD_PLAN) == {"ProduceResults", "Filter", "AllNodesScan"}
    assert collect_operator_types(GOOD_PLAN) == {"ProduceResults", "Expand(All)", "NodeUniqueIndexSeek"}


def test_collect_operator_types_handles_empty():
    assert collect_operator_types({}) == set()
    assert collect_operator_types({"operatorType": "X"}) == {"X"}


def test_guard_flags_allnodesscan():
    # Self-test (decision 10A): a label-less plan must be caught.
    assert find_banned_operators(BAD_PLAN) == {"AllNodesScan"}


def test_guard_passes_indexed_plan():
    # Self-test (decision 10A): an index-seek plan must pass clean.
    assert find_banned_operators(GOOD_PLAN) == set()


def test_iter_generated_queries_builds_all():
    # Enumeration + every ingestion/cleanup query builds without error (no neo4j needed).
    queries = list(iter_generated_queries())
    assert len(queries) > 0
    ingest = [label for label, _, _ in queries if label.startswith("ingest:")]
    assert len(ingest) > 0
    for label, _schema, query in queries:
        assert isinstance(query, str) and query.strip(), label
