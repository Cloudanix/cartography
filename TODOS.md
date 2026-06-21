# TODOS

Deferred work captured from the Neo4j perf plan review (2026-06-21).
See `docs/perf-improvements/plan.md` for the full plan and decisions.

---

## 1. Phase 3 — migrate per-item loaders to `tx.load()`

**What:** Replace hand-written per-item `session.run()` write loops in AWS / GCP / Azure
intel modules with the batched `cartography.client.core.tx.load()` path (UNWIND batching +
managed transactions + auto-indexes), as already done for all OCI modules.

**Why:** Each per-item loop is one Neo4j round-trip and one transaction *per row*. At org
scale (thousands of VPCs/NICs/IAM rows) this dominates sync wall-time and is the largest
remaining scaling bottleneck. `load_graph_data` batches 500 rows/transaction.

**Context:**
- Reference implementation: any `cartography/intel/oci/*` module (migrated in commits
  `36cfa4b`..`317e482`..`61cf547`). Define a `CartographyNodeSchema`, then call `tx.load()`.
- Volume-ranked targets: **GCP compute** (`intel/gcp/compute.py`, per-item VPC/subnet/
  forwarding-rule/NIC/access-config/service-account/firewall loops ~lines 1216–1630) →
  **AWS** (`iam.py`, `rds.py`, `redshift.py`, `route53.py`, `s3.py`, security_groups) →
  **Azure** write-heavy (`cosmosdb.py`, `storage.py`, `subscription.py:101`, `sql.py:336`).
- **Ordering hazard (critical):** loaders have intra-module dependencies — e.g.
  `gcp/compute.py:1501` access-config does `MATCH (nic...) MERGE (ac)` and needs the NIC
  committed first. `load_graph_data`'s per-batch tx boundaries can break this → silently
  missing relationships. Migrate whole dependency chains together (node + dependents in
  load order), not leaf-by-leaf.
- **Memory hazard (critical):** migrating a module whose relationship-target MATCH props
  are unindexed reproduces the CDX-INVENTORY-887 transaction-memory OOM (scan state
  buffered per write tx). Ensure indexes exist first.
- **Hygiene:** each PR migrates a complete module/chain; no file left mixing `load()` and
  raw `run()`. Add a per-module integration test asserting relationship counts pre/post.

**Depends on / blocked by:** Phase 2 EXPLAIN plan guard (TODO #4 / plan §2) must land first —
it is the per-migration merge gate that confirms zero `*Scan` ops before each migration
merges. Do not start Phase 3 until the guard exists.

---

## 2. Phase 4 — audit unanchored cleanup queries

**What:** Identify cleanup jobs that `MATCH (n:Label) WHERE n.lastupdated <> $UPDATE_TAG`
**without** first anchoring on an indexed root, PROFILE them, and fix only those.

**Why:** Cleanup runs every sync. An unanchored job full-label-scans on every iteration of
its `iterationsize` loop. The anchored majority (247/261 JSONs) are already fine, so this is
a small, surgical task — but easy to forget once the bulk of Phase 4 is correctly dropped.

**Context:**
- The earlier draft wrongly claimed all 261 cleanup jobs full-scan. Most anchor via
  `MATCH (:CloudanixWorkspace{id})-[:OWNER]->...-[:RESOURCE]->(n:Label)` (indexed roots) —
  those are correct, leave them.
- Targets: the centrally-generated queries in `cartography/graph/cleanupbuilder.py:82,92,100`,
  plus any hand-written `cartography/data/jobs/cleanup/*.json` whose query starts with a bare
  `MATCH (n:Label) WHERE` and no relationship anchor.
- Do **not** rewrite `<>`→`=` (that changes delete semantics — cleanup must delete rows whose
  tag ≠ this run).

**Depends on / blocked by:** None. Independent, small. Best done with the EXPLAIN guard
available so the audit is mechanical.

---

## 3. `:AzureComputeNode` shared-label refactor (long-term cleanup of 7A)

**What:** Tag both `AzureVirtualMachine` and `AzureVirtualMachineScaleSet` with a shared,
indexed `:AzureComputeNode` label at load time, then have the AKS-link queries
(`azure/compute.py:988,998`) `MATCH (node:AzureComputeNode {...})` on that single label.

**Why:** The near-term fix (decision 7A) templates a UNION over the two labels — correct but
still two label scans and a templated string. A shared indexed label collapses it to one
clean indexed MATCH and removes the label-list templating.

**Context:**
- This is the "cleanest long-term" option (7C) deferred in favour of the minimal-diff 7A.
- Requires: adding the extra label in the VM and VMSS node schemas (`ExtraNodeLabels`),
  a one-time backfill for existing graphs, and an index on `:AzureComputeNode`.
- Only worth doing if more cross-VM/VMSS queries appear; a single call-site doesn't justify
  the schema change + backfill yet.

**Depends on / blocked by:** Azure compute module should ideally be on the schema/`tx.load()`
path first (Phase 3) so `ExtraNodeLabels` is the natural mechanism. Don't backfill twice.

---

## 4. Generalize the EXPLAIN plan guard into reusable tooling

**What:** Extract the Phase 2 EXPLAIN guard (runs `EXPLAIN` on generated ingestion + cleanup
queries, fails on `AllNodesScan` / unindexed `NodeByLabelScan` / `CartesianProduct`) into a
reusable test helper that any module's integration test — and the CI migration gate — can call.

**Why:** The guard is built once for querybuilder + cleanupbuilder output, but its value
compounds if individual module migrations (Phase 3) can assert "my new ingestion query has no
bad plan" with a one-liner, and if it doubles as the per-migration merge gate (decision 12).

**Context:**
- Build the guard first as a concrete integration test (decision 5/13): boot the existing
  test neo4j, seed a few rows so the planner has stats, EXPLAIN every generated query, parse
  plan operators from the result summary, assert no banned operators.
- Ship it with a **self-test** (decision 10): a deliberately label-less query must fail the
  guard; a labelled+indexed query must pass — otherwise the guard can rot to always-green.
- Generalize only after it's proven on the querybuilder/cleanupbuilder suite — don't design
  the abstraction up front.

**Depends on / blocked by:** None to start the concrete guard. Generalization should follow
real second/third use, not precede it.
