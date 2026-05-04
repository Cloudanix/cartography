#!/usr/bin/env python3
"""
Neo4j data comparison tool for pre/post cartography migration validation.

Usage:
    # Compare two live Neo4j instances
    python compare_neo4j.py --before bolt://old-host:7687 --after bolt://new-host:7687

    # Save a snapshot from current instance (run BEFORE migration)
    python compare_neo4j.py --snapshot-save bolt://localhost:7687 --snapshot-file pre_migration.json

    # Compare live instance against saved snapshot (run AFTER migration)
    python compare_neo4j.py --snapshot-load pre_migration.json --after bolt://localhost:7687

    # Full options
    python compare_neo4j.py \
        --before bolt://old:7687 --before-user neo4j --before-password secret \
        --after  bolt://new:7687 --after-user  neo4j --after-password  secret \
        --count-tolerance 0.10 \
        --output report.json
"""

import argparse
import json
import sys
import textwrap
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    from neo4j import GraphDatabase
except ImportError:
    print("ERROR: neo4j driver not installed. Run: pip install neo4j")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

CRITICAL = "CRITICAL"
WARNING  = "WARNING"
INFO     = "INFO"
OK       = "OK"

SEVERITY_ORDER = {CRITICAL: 0, WARNING: 1, INFO: 2, OK: 3}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class Deviation:
    severity: str
    category: str
    label_or_rel: str
    message: str
    before_value: Any
    after_value: Any
    recommendation: str


@dataclass
class ComparisonReport:
    generated_at: str
    before_uri: str
    after_uri: str
    count_tolerance_pct: float
    summary: Dict[str, int] = field(default_factory=dict)
    deviations: List[Deviation] = field(default_factory=list)

    def add(self, deviation: Deviation) -> None:
        self.deviations.append(deviation)

    def sorted_deviations(self) -> List[Deviation]:
        return sorted(self.deviations, key=lambda d: SEVERITY_ORDER[d.severity])

    def build_summary(self) -> None:
        self.summary = {s: 0 for s in [CRITICAL, WARNING, INFO, OK]}
        for d in self.deviations:
            self.summary[d.severity] += 1


# ---------------------------------------------------------------------------
# Neo4j helpers
# ---------------------------------------------------------------------------

def make_driver(uri: str, user: Optional[str], password: Optional[str]):
    auth = (user, password) if user and password else None
    return GraphDatabase.driver(uri, auth=auth)


def run_query(driver, query: str, **params) -> List[Dict]:
    with driver.session() as s:
        return [dict(r) for r in s.run(query, **params)]


# ---------------------------------------------------------------------------
# Snapshot collectors
# ---------------------------------------------------------------------------

def collect_node_counts(driver) -> Dict[str, int]:
    rows = run_query(driver, """
        MATCH (n)
        WITH labels(n) AS lbls
        UNWIND lbls AS lbl
        RETURN lbl AS label, count(*) AS cnt
        ORDER BY lbl
    """)
    return {r["label"]: r["cnt"] for r in rows}


def collect_rel_counts(driver) -> Dict[str, int]:
    rows = run_query(driver, """
        MATCH ()-[r]->()
        RETURN type(r) AS rel_type, count(*) AS cnt
        ORDER BY rel_type
    """)
    return {r["rel_type"]: r["cnt"] for r in rows}


def collect_node_properties(driver) -> Dict[str, Set[str]]:
    rows = run_query(driver, """
        MATCH (n)
        WITH labels(n)[0] AS label, keys(n) AS props
        WHERE label IS NOT NULL
        UNWIND props AS prop
        RETURN label, collect(DISTINCT prop) AS properties
        ORDER BY label
    """)
    return {r["label"]: set(r["properties"]) for r in rows}


def collect_rel_properties(driver) -> Dict[str, Set[str]]:
    rows = run_query(driver, """
        MATCH ()-[r]->()
        WITH type(r) AS rel_type, keys(r) AS props
        UNWIND props AS prop
        RETURN rel_type, collect(DISTINCT prop) AS properties
        ORDER BY rel_type
    """)
    return {r["rel_type"]: set(r["properties"]) for r in rows}


def collect_null_id_counts(driver) -> Dict[str, int]:
    """Count nodes where id IS NULL — indicates broken write."""
    rows = run_query(driver, """
        MATCH (n)
        WHERE n.id IS NULL
        WITH labels(n)[0] AS label
        WHERE label IS NOT NULL
        RETURN label, count(*) AS cnt
        ORDER BY label
    """)
    return {r["label"]: r["cnt"] for r in rows}


def collect_orphan_counts(driver) -> Dict[str, int]:
    """Count nodes with zero relationships."""
    rows = run_query(driver, """
        MATCH (n)
        WHERE NOT (n)--()
        WITH labels(n)[0] AS label
        WHERE label IS NOT NULL
        RETURN label, count(*) AS cnt
        ORDER BY label
    """)
    return {r["label"]: r["cnt"] for r in rows}


def collect_critical_relationships(driver) -> Dict[str, int]:
    """Check critical provider relationships exist."""
    checks = {
        "AWSAccount->EC2Instance (RESOURCE)":
            "MATCH (:AWSAccount)-[:RESOURCE]->(:EC2Instance) RETURN count(*) AS cnt",
        "AWSAccount->AWSRole (AWS_ROLE)":
            "MATCH (:AWSAccount)-[:AWS_ROLE]->(:AWSRole) RETURN count(*) AS cnt",
        "AWSAccount->S3Bucket (RESOURCE)":
            "MATCH (:AWSAccount)-[:RESOURCE]->(:S3Bucket) RETURN count(*) AS cnt",
        "GCPProject->GCPInstance (RESOURCE)":
            "MATCH (:GCPProject)-[:RESOURCE]->(:GCPInstance) RETURN count(*) AS cnt",
        "AzureTenant->AzureSubscription (RESOURCE)":
            "MATCH (:AzureTenant)-[:RESOURCE]->(:AzureSubscription) RETURN count(*) AS cnt",
    }
    results = {}
    for label, query in checks.items():
        try:
            rows = run_query(driver, query)
            results[label] = rows[0]["cnt"] if rows else 0
        except Exception:
            results[label] = -1  # query failed (node type may not exist)
    return results


def collect_module_metadata(driver) -> Dict[str, int]:
    """Count nodes with _module_name set (new NodeSchema pattern)."""
    rows = run_query(driver, """
        MATCH (n)
        WHERE n._module_name IS NOT NULL
        WITH labels(n)[0] AS label
        WHERE label IS NOT NULL
        RETURN label, count(*) AS cnt
        ORDER BY label
    """)
    return {r["label"]: r["cnt"] for r in rows}


def collect_all(driver) -> Dict[str, Any]:
    print("  Collecting node counts...")
    node_counts = collect_node_counts(driver)
    print("  Collecting relationship counts...")
    rel_counts = collect_rel_counts(driver)
    print("  Collecting node property schemas...")
    node_props = {k: list(v) for k, v in collect_node_properties(driver).items()}
    print("  Collecting relationship property schemas...")
    rel_props = {k: list(v) for k, v in collect_rel_properties(driver).items()}
    print("  Collecting null-id nodes...")
    null_ids = collect_null_id_counts(driver)
    print("  Collecting orphan nodes...")
    orphans = collect_orphan_counts(driver)
    print("  Collecting critical relationship counts...")
    critical_rels = collect_critical_relationships(driver)
    print("  Collecting module metadata coverage...")
    module_meta = collect_module_metadata(driver)

    return {
        "node_counts": node_counts,
        "rel_counts": rel_counts,
        "node_props": node_props,
        "rel_props": rel_props,
        "null_ids": null_ids,
        "orphans": orphans,
        "critical_rels": critical_rels,
        "module_meta": module_meta,
        "collected_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Comparison logic
# ---------------------------------------------------------------------------

def pct_change(before: int, after: int) -> float:
    if before == 0:
        return 0.0 if after == 0 else float("inf")
    return abs(after - before) / before


def compare(before: Dict, after: Dict, tolerance: float, report: ComparisonReport) -> None:
    _compare_node_counts(before, after, tolerance, report)
    _compare_rel_counts(before, after, tolerance, report)
    _compare_node_properties(before, after, report)
    _compare_rel_properties(before, after, report)
    _compare_null_ids(after, report)
    _compare_orphans(before, after, report)
    _compare_critical_rels(before, after, report)
    _compare_module_metadata(before, after, report)


def _compare_node_counts(before, after, tolerance, report):
    b_counts: Dict[str, int] = before["node_counts"]
    a_counts: Dict[str, int] = after["node_counts"]
    all_labels = set(b_counts) | set(a_counts)

    for label in sorted(all_labels):
        b = b_counts.get(label, 0)
        a = a_counts.get(label, 0)

        if b == 0 and a > 0:
            report.add(Deviation(
                severity=INFO,
                category="node_counts",
                label_or_rel=label,
                message=f"New node type appeared after migration ({a} nodes)",
                before_value=0,
                after_value=a,
                recommendation=(
                    "Expected if this is a new upstream node type. Verify the sync "
                    "is intentionally writing these nodes and relationships are correct."
                ),
            ))

        elif b > 0 and a == 0:
            report.add(Deviation(
                severity=CRITICAL,
                category="node_counts",
                label_or_rel=label,
                message=f"Node type completely missing after migration (was {b})",
                before_value=b,
                after_value=0,
                recommendation=(
                    f"INVESTIGATE: `{label}` nodes existed before but are gone. "
                    f"Check if the intel module that creates `:{label}` was removed, "
                    f"renamed, or if the cleanup job deleted everything. "
                    f"Re-run the relevant sync module in isolation."
                ),
            ))

        elif pct_change(b, a) > tolerance:
            drop = a < b
            severity = CRITICAL if pct_change(b, a) > 0.30 else WARNING
            direction = "dropped" if drop else "increased"
            pct = pct_change(b, a) * 100
            report.add(Deviation(
                severity=severity,
                category="node_counts",
                label_or_rel=label,
                message=f"Count {direction} by {pct:.1f}% ({b} -> {a})",
                before_value=b,
                after_value=a,
                recommendation=(
                    f"Count drop >30%: check that the intel module for `:{label}` "
                    f"ran successfully and that cleanup jobs are not over-deleting. "
                    f"Cypher: `MATCH (n:{label}) RETURN count(n), n.lastupdated ORDER BY n.lastupdated DESC LIMIT 5`"
                ) if drop else (
                    f"Count increase >tolerance: verify this is expected (e.g. new accounts added). "
                    f"If unexpected, check for duplicate MERGE paths."
                ),
            ))


def _compare_rel_counts(before, after, tolerance, report):
    b_counts: Dict[str, int] = before["rel_counts"]
    a_counts: Dict[str, int] = after["rel_counts"]
    all_rels = set(b_counts) | set(a_counts)

    for rel in sorted(all_rels):
        b = b_counts.get(rel, 0)
        a = a_counts.get(rel, 0)

        if b > 0 and a == 0:
            report.add(Deviation(
                severity=CRITICAL,
                category="rel_counts",
                label_or_rel=rel,
                message=f"Relationship type gone after migration (was {b})",
                before_value=b,
                after_value=0,
                recommendation=(
                    f"Relationship `:{rel}` was present before but is now absent. "
                    f"Check if the relationship was renamed in the upstream NodeSchema, "
                    f"or if the load() call that creates it was removed. "
                    f"Search: `grep -r '{rel}' cartography/models/ cartography/intel/`"
                ),
            ))

        elif b == 0 and a > 0:
            report.add(Deviation(
                severity=INFO,
                category="rel_counts",
                label_or_rel=rel,
                message=f"New relationship type after migration ({a})",
                before_value=0,
                after_value=a,
                recommendation="New upstream relationship — verify it is intentional and correctly scoped.",
            ))

        elif pct_change(b, a) > tolerance and b > 100:
            pct = pct_change(b, a) * 100
            drop = a < b
            severity = CRITICAL if pct > 30 else WARNING
            report.add(Deviation(
                severity=severity,
                category="rel_counts",
                label_or_rel=rel,
                message=f"Count {'dropped' if drop else 'increased'} by {pct:.1f}% ({b} -> {a})",
                before_value=b,
                after_value=a,
                recommendation=(
                    f"Large drop in `:{rel}` relationships. Check that both source and target "
                    f"node types are still being synced before the relationship is created. "
                    f"Cypher: `MATCH ()-[r:{rel}]->() RETURN count(r)`"
                ) if drop else (
                    f"Large increase in `:{rel}`. Check for duplicate sync runs or missing dedup."
                ),
            ))


def _compare_node_properties(before, after, report):
    b_props: Dict[str, List[str]] = before["node_props"]
    a_props: Dict[str, List[str]] = after["node_props"]
    shared_labels = set(b_props) & set(a_props)

    for label in sorted(shared_labels):
        b = set(b_props[label])
        a = set(a_props[label])
        removed = b - a
        added = a - b

        # Ignore internal cartography fields as "additions"
        added = added - {"_module_name", "_module_version", "firstseen"}

        if removed:
            report.add(Deviation(
                severity=WARNING,
                category="node_properties",
                label_or_rel=label,
                message=f"Properties removed: {sorted(removed)}",
                before_value=sorted(removed),
                after_value=[],
                recommendation=(
                    f"Properties {sorted(removed)} no longer appear on `:{label}` nodes. "
                    f"Check if they were renamed (e.g. camelCase to snake_case) in the upstream "
                    f"NodeSchema. Search the model: `grep -r '{label}' cartography/models/`. "
                    f"If renamed, any downstream Cypher queries using old names will break."
                ),
            ))

        if added:
            report.add(Deviation(
                severity=INFO,
                category="node_properties",
                label_or_rel=label,
                message=f"New properties: {sorted(added)}",
                before_value=[],
                after_value=sorted(added),
                recommendation=(
                    "New properties are expected from upstream additions. "
                    "No action required unless your downstream queries depend on their absence."
                ),
            ))


def _compare_rel_properties(before, after, report):
    b_props: Dict[str, List[str]] = before["rel_props"]
    a_props: Dict[str, List[str]] = after["rel_props"]
    shared_rels = set(b_props) & set(a_props)

    for rel in sorted(shared_rels):
        b = set(b_props[rel])
        a = set(a_props[rel])
        removed = b - a - {"_module_name", "_module_version"}

        if removed:
            report.add(Deviation(
                severity=WARNING,
                category="rel_properties",
                label_or_rel=rel,
                message=f"Relationship properties removed: {sorted(removed)}",
                before_value=sorted(removed),
                after_value=[],
                recommendation=(
                    f"Properties {sorted(removed)} no longer appear on `:{rel}` relationships. "
                    f"Check the upstream CartographyRelProperties for this relationship type."
                ),
            ))


def _compare_null_ids(after, report):
    null_ids: Dict[str, int] = after["null_ids"]
    for label, cnt in sorted(null_ids.items()):
        if cnt > 0:
            report.add(Deviation(
                severity=CRITICAL,
                category="data_integrity",
                label_or_rel=label,
                message=f"{cnt} nodes have null id — broken write",
                before_value="n/a",
                after_value=cnt,
                recommendation=(
                    f"Null `id` means the MERGE key is missing. These nodes will not be "
                    f"correctly deduped or cleaned up. "
                    f"Check the `id: PropertyRef(...)` mapping in the NodeSchema for `:{label}`. "
                    f"Fix: `MATCH (n:{label}) WHERE n.id IS NULL RETURN n LIMIT 10` to inspect, "
                    f"then re-run the sync after fixing the schema."
                ),
            ))


def _compare_orphans(before, after, report):
    b_orphans: Dict[str, int] = before["orphans"]
    a_orphans: Dict[str, int] = after["orphans"]

    # Only flag if orphan count increased significantly
    all_labels = set(b_orphans) | set(a_orphans)
    for label in sorted(all_labels):
        b = b_orphans.get(label, 0)
        a = a_orphans.get(label, 0)
        if a > b and a > 10:
            increase = a - b
            report.add(Deviation(
                severity=WARNING,
                category="orphan_nodes",
                label_or_rel=label,
                message=f"Orphan count increased by {increase} ({b} -> {a})",
                before_value=b,
                after_value=a,
                recommendation=(
                    f"More `:{label}` nodes have no relationships. This usually means the "
                    f"relationship-creation step ran after the node write but is now missing or failing. "
                    f"Check that the `load()` call for relationships to `:{label}` still runs "
                    f"in the intel module. "
                    f"Cypher: `MATCH (n:{label}) WHERE NOT (n)--() RETURN n LIMIT 10`"
                ),
            ))


def _compare_critical_rels(before, after, report):
    b_crit: Dict[str, int] = before["critical_rels"]
    a_crit: Dict[str, int] = after["critical_rels"]

    for path, b in sorted(b_crit.items()):
        a = a_crit.get(path, 0)
        if b > 0 and a == 0:
            report.add(Deviation(
                severity=CRITICAL,
                category="critical_relationships",
                label_or_rel=path,
                message=f"Critical path has 0 relationships (was {b})",
                before_value=b,
                after_value=0,
                recommendation=(
                    f"The path `{path}` had {b} relationships before and now has none. "
                    f"This is a high-impact regression — graph traversals will return no results. "
                    f"Re-run the relevant sync module in isolation and check for errors. "
                    f"Verify both node types in the path are being synced successfully."
                ),
            ))
        elif b > 0 and pct_change(b, a) > 0.30:
            pct = pct_change(b, a) * 100
            report.add(Deviation(
                severity=WARNING,
                category="critical_relationships",
                label_or_rel=path,
                message=f"Critical path dropped {pct:.1f}% ({b} -> {a})",
                before_value=b,
                after_value=a,
                recommendation=(
                    f"Large drop in critical path `{path}`. Verify both source and target "
                    f"node types synced successfully in this run."
                ),
            ))


def _compare_module_metadata(before, after, report):
    b_meta: Dict[str, int] = before["module_meta"]
    a_meta: Dict[str, int] = after["module_meta"]

    # After migration, _module_name should appear on many more nodes (NodeSchema pattern)
    total_before = sum(b_meta.values())
    total_after  = sum(a_meta.values())

    if total_before == 0 and total_after > 0:
        report.add(Deviation(
            severity=INFO,
            category="module_metadata",
            label_or_rel="all",
            message=f"_module_name now present on {total_after} nodes (new NodeSchema pattern)",
            before_value=0,
            after_value=total_after,
            recommendation=(
                "Expected after migrating to upstream NodeSchema. "
                "No action required. _module_name and _module_version track which "
                "cartography module wrote each node."
            ),
        ))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(report: ComparisonReport) -> None:
    deviations = report.sorted_deviations()
    report.build_summary()

    width = 80
    print("\n" + "=" * width)
    print("  CARTOGRAPHY MIGRATION COMPARISON REPORT")
    print(f"  Generated: {report.generated_at}")
    print(f"  Before:    {report.before_uri}")
    print(f"  After:     {report.after_uri}")
    print(f"  Tolerance: {report.count_tolerance_pct * 100:.0f}%")
    print("=" * width)

    print(f"\nSUMMARY")
    print(f"  {CRITICAL}: {report.summary.get(CRITICAL, 0)}")
    print(f"  {WARNING}:  {report.summary.get(WARNING, 0)}")
    print(f"  {INFO}:     {report.summary.get(INFO, 0)}")

    if not deviations:
        print("\n  No deviations found. Data looks consistent.")
        return

    for severity in [CRITICAL, WARNING, INFO]:
        items = [d for d in deviations if d.severity == severity]
        if not items:
            continue

        print(f"\n{'=' * width}")
        print(f"  {severity} ({len(items)} items)")
        print("=" * width)

        for d in items:
            print(f"\n  [{d.severity}] {d.category} | {d.label_or_rel}")
            print(f"  Message:  {d.message}")
            print(f"  Before:   {d.before_value}")
            print(f"  After:    {d.after_value}")
            print(f"  Action:   ", end="")
            # Wrap recommendation at 76 chars, indent continuation lines
            wrapped = textwrap.fill(d.recommendation, width=74,
                                    subsequent_indent="            ")
            print(wrapped)

    print("\n" + "=" * width)
    total = len(deviations)
    critical = report.summary.get(CRITICAL, 0)
    if critical > 0:
        print(f"  RESULT: FAIL — {critical} critical issue(s) require immediate attention.")
        print(f"  DO NOT promote this build to production until critical items are resolved.")
    elif report.summary.get(WARNING, 0) > 0:
        print(f"  RESULT: WARN — {total} deviation(s) found. Review warnings before promoting.")
    else:
        print(f"  RESULT: PASS — Only informational deviations. Safe to promote.")
    print("=" * width + "\n")


# ---------------------------------------------------------------------------
# Snapshot I/O
# ---------------------------------------------------------------------------

def save_snapshot(data: Dict, path: str) -> None:
    # Sets are not JSON-serializable — already converted to lists in collect_all()
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"Snapshot saved to {path}")


def load_snapshot(path: str) -> Dict:
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Compare Neo4j data before and after a cartography migration.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Connection args
    p.add_argument("--before",          help="Neo4j bolt URI for the BEFORE instance")
    p.add_argument("--before-user",     default=None)
    p.add_argument("--before-password", default=None)
    p.add_argument("--after",           help="Neo4j bolt URI for the AFTER instance")
    p.add_argument("--after-user",      default=None)
    p.add_argument("--after-password",  default=None)

    # Snapshot mode
    p.add_argument("--snapshot-save",   help="URI to snapshot from (saves to --snapshot-file)")
    p.add_argument("--snapshot-load",   help="Path to load a pre-saved snapshot as 'before' data")
    p.add_argument("--snapshot-file",   default="cartography_snapshot.json",
                   help="File path for saving/loading snapshots (default: cartography_snapshot.json)")

    # Options
    p.add_argument("--count-tolerance", type=float, default=0.10,
                   help="Acceptable count deviation fraction (default: 0.10 = 10%%)")
    p.add_argument("--output",          help="Write JSON report to this file in addition to stdout")

    return p


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    # --- Snapshot save mode ---
    if args.snapshot_save:
        print(f"Connecting to {args.snapshot_save} to save snapshot...")
        driver = make_driver(args.snapshot_save, args.before_user, args.before_password)
        data = collect_all(driver)
        driver.close()
        save_snapshot(data, args.snapshot_file)
        print("Done. Run with --snapshot-load after migration to compare.")
        return 0

    # --- Resolve 'before' data ---
    if args.snapshot_load:
        print(f"Loading snapshot from {args.snapshot_load}...")
        before_data = load_snapshot(args.snapshot_load)
        before_uri = f"snapshot:{args.snapshot_load}"
    elif args.before:
        print(f"Connecting to BEFORE instance: {args.before}")
        driver = make_driver(args.before, args.before_user, args.before_password)
        before_data = collect_all(driver)
        driver.close()
        before_uri = args.before
    else:
        parser.error("Provide --before or --snapshot-load")
        return 1

    # --- Resolve 'after' data ---
    if not args.after:
        parser.error("--after is required for comparison")
        return 1

    print(f"Connecting to AFTER instance: {args.after}")
    after_driver = make_driver(args.after, args.after_user, args.after_password)
    after_data = collect_all(after_driver)
    after_driver.close()

    # --- Compare ---
    report = ComparisonReport(
        generated_at=datetime.utcnow().isoformat(),
        before_uri=before_uri,
        after_uri=args.after,
        count_tolerance_pct=args.count_tolerance,
    )

    print("\nRunning comparison...")
    compare(before_data, after_data, args.count_tolerance, report)
    report.build_summary()

    # --- Output ---
    print_report(report)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(
                {
                    "report": {
                        "generated_at": report.generated_at,
                        "before_uri": report.before_uri,
                        "after_uri": report.after_uri,
                        "tolerance_pct": report.count_tolerance_pct,
                        "summary": report.summary,
                    },
                    "deviations": [asdict(d) for d in report.sorted_deviations()],
                    "before_snapshot": before_data,
                    "after_snapshot": after_data,
                },
                f,
                indent=2,
                default=str,
            )
        print(f"Full JSON report written to {args.output}")

    # Exit code: 1 if any CRITICAL, 0 otherwise
    return 1 if report.summary.get(CRITICAL, 0) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
