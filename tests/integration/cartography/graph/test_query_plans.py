"""
Neo4j query-plan guard (Phase 2 of docs/perf-improvements/plan.md).

Runs EXPLAIN against a live neo4j and fails if any generated ingestion/cleanup query plans an
AllNodesScan (a query with no anchoring label/index). Indexes are created per schema before
EXPLAIN so the plan reflects production index availability (decisions 1A/12A).

The pure detection logic lives in plan_guard.py and is unit-tested without a database in
tests/unit/cartography/graph/test_plan_guard.py.
"""
import neo4j

from cartography.client.core.tx import ensure_indexes
from tests.integration.cartography.graph.plan_guard import collect_operator_types
from tests.integration.cartography.graph.plan_guard import find_banned_operators
from tests.integration.cartography.graph.plan_guard import iter_generated_queries

# Schemas whose generated queries are known to plan a banned operator and are pending a fix.
# Empty = the guard is a hard gate. Add a label here (with a TODO) only to unblock CI while the
# underlying query is fixed; do not let this grow silently.
KNOWN_OFFENDERS: set = set()


def _explain_plan(neo4j_session: neo4j.Session, query: str) -> dict:
    # EXPLAIN plans without executing and does not require parameter values to be supplied.
    result = neo4j_session.run("EXPLAIN " + query)
    summary = result.consume()
    return summary.plan


def test_guard_detects_allnodesscan(neo4j_session):
    # Self-test (decision 10A): a deliberately label-less query MUST be flagged, otherwise the
    # guard could silently rot to always-green.
    plan = _explain_plan(neo4j_session, "MATCH (n) WHERE n.plan_guard_probe = 'x' RETURN n")
    assert "AllNodesScan" in collect_operator_types(plan)


def test_guard_passes_indexed_lookup(neo4j_session):
    # Self-test (decision 10A): an indexed label lookup MUST pass clean.
    neo4j_session.run("CREATE INDEX IF NOT EXISTS FOR (n:PlanGuardFoo) ON (n.id)")
    plan = _explain_plan(neo4j_session, "MATCH (n:PlanGuardFoo {id: 'x'}) RETURN n")
    assert find_banned_operators(plan) == set()


def test_generated_queries_have_no_allnodesscan(neo4j_session):
    # Sweep every generated ingestion + cleanup query (decision 13A: all queries).
    offenders: dict = {}
    for label, schema, query in iter_generated_queries():
        ensure_indexes(neo4j_session, schema)
        banned = find_banned_operators(_explain_plan(neo4j_session, query))
        schema_name = type(schema).__name__
        if banned and schema_name not in KNOWN_OFFENDERS:
            offenders[label] = sorted(banned)
    assert not offenders, f"generated queries with banned plan operators: {offenders}"
