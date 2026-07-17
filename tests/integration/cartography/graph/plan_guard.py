"""
Helpers for the Neo4j query-plan guard (Phase 2 of docs/perf-improvements/plan.md).

Pure, neo4j-free logic so it can be unit-tested without a live database:
  - walk an EXPLAIN plan tree and collect its operator types
  - flag banned operators (AllNodesScan = a query with no anchoring label/index)
  - enumerate every generated ingestion + cleanup query from the model schemas

The integration test (test_query_plans.py) feeds real EXPLAIN plans through
find_banned_operators(); the unit test (tests/unit/.../test_plan_guard.py) feeds
canned plan dicts so the detection logic is validated locally.
"""
import importlib
import pkgutil
from typing import Dict
from typing import Iterator
from typing import List
from typing import Set
from typing import Tuple

import cartography.models
from cartography.graph.cleanupbuilder import build_cleanup_queries
from cartography.graph.querybuilder import build_ingestion_query
from cartography.models.core.nodes import CartographyNodeSchema

# AllNodesScan = the planner found no label/index anchor and must scan every node in the graph.
# This is the operator the plan guard exists to catch. NodeByLabelScan is intentionally NOT
# banned: a bounded label scan (e.g. cleanup traversing from an indexed root) is acceptable.
BANNED_OPERATORS: Set[str] = {"AllNodesScan"}


def collect_operator_types(plan: Dict) -> Set[str]:
    """
    Recursively collect every operatorType from a Neo4j EXPLAIN plan tree.
    A plan node is a dict with an 'operatorType' string and a 'children' list of sub-plans
    (the shape of neo4j.ResultSummary.plan).
    """
    if not isinstance(plan, dict):
        return set()
    operators: Set[str] = set()
    op = plan.get("operatorType")
    if op:
        # operatorType can carry detail after '@', e.g. "AllNodesScan@neo4j" - keep the bare name.
        operators.add(op.split("@")[0])
    for child in plan.get("children", []) or []:
        operators |= collect_operator_types(child)
    return operators


def find_banned_operators(plan: Dict, banned: Set[str] = BANNED_OPERATORS) -> Set[str]:
    """Return the banned operators present in the plan (empty set => plan is acceptable)."""
    return collect_operator_types(plan) & banned


def all_concrete_node_schemas() -> List[CartographyNodeSchema]:
    """
    Import every module under cartography.models, then instantiate every concrete
    CartographyNodeSchema subclass. Abstract bases are skipped.
    """
    for mod in pkgutil.walk_packages(cartography.models.__path__, cartography.models.__name__ + "."):
        importlib.import_module(mod.name)

    def _concrete(cls: type) -> Set[type]:
        found: Set[type] = set()
        for sub in cls.__subclasses__():
            if not getattr(sub, "__abstractmethods__", None):
                found.add(sub)
            found |= _concrete(sub)
        return found

    return [cls() for cls in _concrete(CartographyNodeSchema)]


def iter_generated_queries() -> Iterator[Tuple[str, CartographyNodeSchema, str]]:
    """
    Yield (label, node_schema, query) for every generated ingestion and cleanup query.

    Cleanup queries require a sub_resource_relationship; schemas without one (top-level
    "root"/"tenant" nodes) raise ValueError from build_cleanup_queries and are skipped for
    cleanup but still yield their ingestion query.
    """
    for schema in all_concrete_node_schemas():
        name = type(schema).__name__
        yield f"ingest:{name}", schema, build_ingestion_query(schema)
        try:
            cleanup_queries = build_cleanup_queries(schema)
        except ValueError:
            continue
        for i, query in enumerate(cleanup_queries):
            yield f"cleanup:{name}:{i}", schema, query
