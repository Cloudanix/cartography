# Neo4j Scaling — Performance Improvement Plan

Status: draft · Owner: backend · Last updated: 2026-06-21

This plan analyzes the cartography codebase against four well-known Neo4j scaling
remediations and lays out concrete, prioritized work. Every finding below is
backed by a `file:line` reference verified against the current `main`.

The four remediations:

1. Use the UNWIND pattern for batching
2. Use managed transactions
3. Ensure indexes exist for key fields
4. Use EXPLAIN/PROFILE to find inefficient APIs (AllNodesScan, etc.)

---

## TL;DR — what to fix, in order

| # | Fix | Why | Effort | Impact |
|---|-----|-----|--------|--------|
| 1 | Add labels to label-less / unindexed `MATCH`es (`azure/compute.py:988,998`, `gcp/compute.py:1501`, `gcp/spanner.py:157`) | AllNodesScan / full-label-scan on every run | S | 🔴 High |
| 2 | Index properties used in loader `MATCH`/`WHERE` that aren't `id`/relationship targets (e.g. `GCPSpannerInstance.config`, `AzureCluster.name`) | Full label scan per UNWIND batch | S | 🔴 High |
| 3 | Migrate hottest hand-written per-item loops to `load()` / `load_graph_data()` (GCP compute, AWS iam/rds, Azure) | One round-trip per row instead of per 500-row batch | L | 🔴 High |
| 4 | Wrap remaining raw `session.run()` writes in managed transactions (incl. `ensure_indexes`) | No retry on `TransientError` | M | 🟠 Med |
| 5 | Add an integration EXPLAIN plan guard (with self-test) in CI | Catch AllNodesScan regressions before deploy; merge gate for migrations | M | 🟠 Med |
| 6 | PROFILE only the *unanchored* cleanup queries (NOT the 247 anchored ones) | Most cleanup jobs already traverse indexed roots — see correction below | S | 🟢 Low |

S = small (hours), M = medium (days), L = large (weeks, incremental).

> **Plan-review correction (2026-06-21):** an earlier draft claimed "261 cleanup jobs do full
> label scans via `lastupdated <> $UPDATE_TAG`". **Wrong.** 247/261 anchor on indexed ids first
> (`MATCH (:CloudanixWorkspace{id})-[:OWNER]->(:AWSOrganization{id})-[:OWNER]->(:AWSAccount{id})-[:RESOURCE]->(n:Label) WHERE n.lastupdated <> $UPDATE_TAG`),
> so they scan a bounded subgraph, not a whole label. Rewriting `<>`→`=` would also be
> semantically wrong (cleanup deletes rows whose tag ≠ this run). Phase 4 is therefore narrowed
> to only the centrally-generated `cleanupbuilder.py` queries and any genuinely unanchored job.

## Review decisions (2026-06-21, plan-review/BIG)

Recorded authoritatively; phase sections below follow these.

| # | Decision | Choice |
|---|----------|--------|
| 1 | EXPLAIN guard level | **Integration, real EXPLAIN** against live-neo4j; seed rows so planner stats aren't empty |
| 2 | Index source of truth | **Schema `extra_index=True` canonical** for migrated modules; `indexes.cypher` only pre-migration; migrating a module *moves* its entries |
| 3 | Azure AKS fix depth | Fix label scan **and** add `AzureCluster(name)` index in the same change |
| 4 | Phase 3 ordering | **Guardrails first (Phase 2), then chain-migrate** whole dependency chains together |
| 5 | Phase 4 scope | Narrow to generated + unanchored jobs; PROFILE first; doc corrected (above) |
| 6 | Index enforcement | **EXPLAIN guard enforces** the index-coverage rule; **no** separate static Cypher lint |
| 7 | AKS query shape | One query per link-step, **templated UNION** over the label list (no 4× copy-paste) |
| 8 | Migration hygiene | **Atomic per module/chain**; no file committed in mixed `load()`+raw-`run()` state |
| 9 | AKS link test | **Red-first** integration test (HAS_NODE for VM + VMSS + AgentPool) before the 7A rewrite |
| 10 | Guard self-test | Ship guard with **bad+good fixtures** (label-less must fail, indexed must pass) |
| 11 | ensure_indexes retry test | **Skip** — driver contract, trivial wrapper |
| 12 | Migrate-OOM safety | **EXPLAIN guard is the per-migration merge gate** (zero `*Scan` before merge) — prevents reproducing CDX-INVENTORY-887 |
| 13 | Guard CI scope | Run over **all** generated queries (EXPLAIN doesn't execute; neo4j already up) |
| 14 | Batch size | **Leave 500**; tune per-module only if PROFILE shows need |

---

## Phase status

Legend: ✅ done · 🔵 in progress · ⚪ not started · ⛔ blocked/deferred

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Query/index fixes + `ensure_indexes` managed-tx wrap | 🔵 in progress |
| 2 | Integration EXPLAIN plan guard (+ self-test) | ⚪ not started |
| 3 | Migrate per-item loaders to `tx.load()` | ⛔ deferred — gated on Phase 2 |
| 4 | PROFILE unanchored cleanup queries | ⚪ not started |

### Phase 1 checklist

| # | Change | Test | Unit/lint here | Integration (CI) | Commit |
|---|--------|------|----------------|------------------|--------|
| 1.1 | `ensure_indexes` raw `run` → `execute_write` (`tx.py:234`) | unit (mock session) | ⚪ | n/a | ⚪ |
| 1.2 | `gcp/compute.py:1501` `MATCH (nic)` → `:GCPNetworkInterface` | existing `test_compute.py:346` | n/a | ⚪ pending | ⚪ |
| 1.3 | `gcp/spanner.py:157` + index `GCPSpannerInstance(config)` | existing `test_spanner.py` | n/a | ⚪ pending | ⚪ |
| 1.4 | `azure/compute.py` AKS templated UNION + `AzureCluster(name)` index | new red-first `test_aks.py` (9A) | n/a | ⚪ pending | ⚪ |

> **Validation note:** neo4j/docker unavailable in the dev sandbox, so integration tests can't
> run here (decision: unit-validate + lint locally, run `make test_integration` in CI). Each
> Phase 1 commit notes its integration test as pending CI.

---

## How data flows today (baseline)

The modern, efficient path already exists and is the migration target:

```
intel module
  └─ tx.load(session, node_schema, dict_list)            cartography/client/core/tx.py:237
        ├─ ensure_indexes(session, node_schema)           tx.py:218  → auto CREATE INDEX
        └─ load_graph_data(session, query, dict_list)     tx.py:194
              └─ for batch in batch(dict_list, size=500): tx.py:209
                    session.execute_write(write_list_of_dicts_tx, query, DictList=batch)
```

- `build_ingestion_query()` (`cartography/graph/querybuilder.py:349`) generates a single
  `UNWIND $DictList AS item MERGE (...) SET ...` query — correct batched pattern.
- `build_create_index_queries()` (`querybuilder.py:404`) auto-creates indexes for the
  node's `id`, `lastupdated`, every relationship `TargetNodeMatcher` field, and any
  `PropertyRef(extra_index=True)`.
- Static baseline indexes live in `cartography/data/indexes.cypher` (475 `CREATE INDEX`
  statements), applied once before sync via `cartography/intel/create_indexes.py`.

OCI is fully migrated to this path (10 modules). AWS, GCP, and Azure are largely **not**,
and that is where the scaling cost concentrates.

---

## 1. UNWIND batching

### What's good
- `load_graph_data()` batches at **500 rows/transaction** via UNWIND — the right pattern.
- All OCI modules use it. The querybuilder makes it the default for new code.

### Gaps — per-item loops (one transaction per row)
These are the scaling bottleneck: a Python `for` loop calling `session.run()` once per
item means N network round-trips and N transactions instead of `ceil(N/500)`.

- **GCP compute** — many per-item `MERGE` loops:
  `cartography/intel/gcp/compute.py` VPC, subnet, forwarding-rule, NIC, access-config,
  service-account, firewall loaders (functions around lines 1216–1630). Highest row
  counts in a typical org; top migration target.
- **AWS** — per-item loops in `aws/iam.py`, `aws/rds.py`, `aws/redshift.py`,
  `aws/load_balancers.py`, `aws/load_balancer_v2s.py`, `aws/security_groups.py`,
  `aws/route53.py`, `aws/s3.py`.
- **Azure** — per-item loops in `azure/subscription.py:101`, `azure/sql.py:336`,
  plus cosmosdb/storage write-heavy modules.
- **Misc** — `digitalocean/compute.py`, `pagerduty/services.py`, `github/repos.py`.

### Plan
1. Rank modules by typical row volume (GCP compute, AWS iam/rds first).
2. For each: define a `CartographyNodeSchema` (if missing) and replace the
   hand-written loop with `tx.load(...)`. This gets UNWIND batching, managed
   transactions, and auto-indexes in one move.
3. Where a full schema migration is too large, intermediate win: rewrite the loop
   body as a single `UNWIND $DictList AS item ...` query and call `load_graph_data()`
   directly with the existing query string.
4. Track migration in a checklist (one row per module) so coverage is visible.

Reference implementation to copy: any OCI module, e.g. `cartography/intel/oci/compute.py`.

---

## 2. Managed transactions

### What's good
- `load_graph_data()`, `GraphJob`/`GraphStatement` (cleanup & analysis jobs), and
  several modules (Azure IAM, GitLab) already use `execute_write`/`execute_read`,
  which retry on `TransientError` with backoff (`cartography/graph/statement.py`,
  `cartography/graph/job.py`).

### Gaps — raw auto-commit `session.run()`
Raw `neo4j_session.run(...)` is auto-commit with **no retry**. A transient error
(leader switch, memory pressure) fails the whole sync stage. Largest clusters of raw
writes: `azure/cosmosdb.py`, `azure/storage.py`, plus the per-item loaders in §1.

One specific infra case worth fixing regardless of the broader migration:

- `cartography/client/core/tx.py:234` — `ensure_indexes()` runs each `CREATE INDEX`
  via raw `neo4j_session.run(query)` in a loop. Low volume but runs on every `load()`;
  wrap in `execute_write` for retry consistency.

### Plan
- The §1 migration to `tx.load()` eliminates most raw writes for free.
- For code not yet migrated, wrap writes in `session.execute_write(tx_fn, ...)` where
  `tx_fn` calls `tx.run(...)`. Prefer migration over piecemeal wrapping when a schema
  is feasible.
- Fix `ensure_indexes()` independently (small, isolated).

Note: read queries in loaders (e.g. `cve/feed.py:23`) should use
`execute_read(read_list_of_values_tx, query)` from `tx.py` rather than raw `.run()`.

---

## 3. Indexes for key fields

### What's good
- Two-tier coverage: static `indexes.cypher` (baseline, pre-sync) + dynamic
  `build_create_index_queries()` (per-load, from schema). Auto-covers `id`,
  `lastupdated`, relationship `TargetNodeMatcher` fields, and `extra_index=True`.

### Gaps — properties matched in loaders but not indexed
The auto-indexer only sees the schema. When a **hand-written loader** `MATCH`es a node
on a property that is neither `id` nor a relationship-target field, no index is created
→ full label scan per batch. Recent commit `fb37bc143` fixed exactly this class for OCI
attachment loaders (`vnic_id`, `boot_volume_id`, …) by adding them to `indexes.cypher`.

Confirmed live instances:

- `cartography/intel/gcp/spanner.py:157` — `MATCH (instance:GCPSpannerInstance{config: instance_config.id})`.
  `config` is not indexed (only `id` is). Runs inside relationship linking.
- Analysis/cleanup jobs filter on un-indexed props like `exposed_internet`,
  `anonymous_access` across many labels (`cartography/data/jobs/`).

### Plan
1. **Short term:** add the missing indexes to `indexes.cypher` (mirror the `fb37bc143`
   approach) for confirmed hot props — start with `GCPSpannerInstance(config)`.
2. **Better:** mark the property `extra_index=True` on its `PropertyRef` in the node
   schema so the index travels with the model (only works once the module is migrated
   to a schema; otherwise use indexes.cypher).
3. **Systematic:** write a lint/test that scans loader Cypher for `MATCH (x:Label{prop: ...})`
   where `prop != id` and asserts a matching index exists in `indexes.cypher` or the
   schema. This prevents the gap class from recurring. (See §4 tooling.)

---

## 4. EXPLAIN / inefficient APIs (AllNodesScan)

### Confirmed offenders
- **AllNodesScan — label-less `MATCH`:**
  - `cartography/intel/gcp/compute.py:1501` — `MATCH (nic{id: $NicId})` (no label).
    Fix: `MATCH (nic:GCPNetworkInterface{id: $NicId})`.
  - `cartography/intel/azure/compute.py:989` and `:999` —
    `MATCH (node) WHERE node:AzureVirtualMachine OR node:AzureVirtualMachineScaleSet`.
    Label-less scan then filter. Fix: run two labelled `MATCH`es / `UNION`, or anchor on
    an indexed property.
- **Full label scan on non-indexed property:** `gcp/spanner.py:157` (see §3).
- **Cartesian-style linking:** `cartography/intel/aws/route53.py:119,128,137` —
  `MATCH (n:AWSDNSRecord) WITH n MATCH (l:LoadBalancer{dnsname: n.value})`. The target
  match keys on `dnsname`; confirm those are indexed and that the planner isn't doing an
  n×m join. Rewrite as a single UNWIND + indexed lookup if the plan is bad.
- **Cleanup scans:** `cartography/graph/cleanupbuilder.py:82,92,100` generate
  `WHERE n.lastupdated <> $UPDATE_TAG`. The *hand-written* job JSONs (247/261) anchor on
  indexed ids before this filter (bounded subgraph — fine). The *generated* cleanupbuilder
  queries are the ones to PROFILE: confirm they anchor via the sub-resource relationship
  (which is indexed) rather than starting from a bare `MATCH (n:Label)`. Do **not** rewrite
  `<>`→`=` (different semantics).

### No instrumentation today
There is zero use of `EXPLAIN`/`PROFILE` in code or tests. Bad plans ship undetected.

### Plan
1. Fix the three confirmed AllNodesScan/full-scan sites above (small, high value).
2. Add a **plan-guard test**: a unit/integration test that runs `EXPLAIN <query>` against
   a test Neo4j for each generated ingestion/cleanup query (querybuilder + cleanupbuilder
   are the choke points — testing them covers most modules) and **fails if the plan
   contains `AllNodesScan`** (and optionally `NodeByLabelScan` without an index or a
   `CartesianProduct`). Parse `EXPLAIN` plan operators from the result summary.
3. For `lastupdated <> $UPDATE_TAG`: evaluate alternatives — e.g. keep an index on
   `lastupdated` and confirm the planner uses a range/scan efficiently, or restructure
   cleanup to traverse from the sub-resource anchor (which is indexed) before filtering.
   Measure with PROFILE before/after; don't change semantics blindly.

---

## Suggested execution order

**Phase 1 — quick, high-value (days):**
- Fix label-less/unindexed MATCHes: `gcp/compute.py:1501`, `azure/compute.py:989/999`,
  `gcp/spanner.py:157` (+ index).
- Wrap `ensure_indexes()` in `execute_write`.

**Phase 2 — guardrails (days):**
- EXPLAIN plan-guard test over querybuilder + cleanupbuilder outputs.
- Index-coverage lint for non-`id` loader MATCHes.

**Phase 3 — migration (incremental, weeks):**
- Migrate per-item loaders to `tx.load()`, volume-ranked: GCP compute → AWS iam/rds →
  Azure write-heavy modules → misc. Each migration removes raw writes (§2) and gains
  UNWIND batching (§1) + auto-indexes (§3) at once.

**Phase 4 — cleanup-scan optimization (narrowed, after measurement):**
- PROFILE only the generated `cleanupbuilder.py` queries + any unanchored hand-written job.
  Do not touch the 247 anchored jobs. (See TODOS.md "unanchored-cleanup audit".)

---

## What already exists (reused, not rebuilt)

| Sub-problem | Existing code reused | Verdict |
|---|---|---|
| UNWIND batching | `load_graph_data` (`tx.py:194`, batch=500) | Reuse — migration target |
| Managed tx + retry | `execute_write`/`execute_read`, `GraphJob`/`GraphStatement` | Reuse |
| Index auto-gen | `build_create_index_queries` (`querybuilder.py:404`) | Reuse |
| Static index baseline | `data/indexes.cypher` (475 indexes) | Reuse |
| Migration recipe | OCI modules (`intel/oci/*`, just-merged) | Copy pattern |
| GCP NIC↔AccessConfig test | `tests/integration/.../gcp/test_compute.py:346` | Covers C1 already |

No new services or classes are introduced. The plan is "apply the existing `tx.load()`
path to un-migrated modules" + 3 query/index fixes + 1 test harness.

## NOT in scope (considered, deferred)

| Item | Rationale |
|---|---|
| Rewrite `lastupdated <>`→`=` across cleanup jobs | Premise was wrong; anchored jobs are fine, and `<>` is required semantics |
| Separate static Cypher-lint tool | Redundant with the EXPLAIN guard (decision 6); brittle string parser |
| `:AzureComputeNode` shared-label refactor (7C) | Cleaner long-term but needs schema change + backfill → TODOS.md |
| Per-load batch-size parameter (14B/C) | Speculative knob; 500 is the conservative memory choice |
| `ensure_indexes` retry unit test | Driver contract, trivial wrapper (decision 11) |
| Bumping `dbms.memory.transaction.total.max` | Masks the cause; index-before-migrate is the real fix |
| Phase 3 mass migration (now) | Deferred until Phase 2 guardrails land (decision 4) → TODOS.md |

---

## Verification

For every change, capture before/after `PROFILE` of the affected query (db hits, rows,
operators) on a representative dataset. The Phase 2 plan-guard test then prevents
regressions. Migrations are behavior-preserving — existing module integration tests must
stay green.

## Key file reference

| Concern | File:line |
|---------|-----------|
| Batched load entrypoint | `cartography/client/core/tx.py:237` (`load`), `:194` (`load_graph_data`), `:209` (batch=500) |
| Raw run in ensure_indexes | `cartography/client/core/tx.py:234` |
| Ingestion query (UNWIND) | `cartography/graph/querybuilder.py:349` |
| Auto index generation | `cartography/graph/querybuilder.py:404` |
| Static indexes | `cartography/data/indexes.cypher` (475 indexes) |
| Cleanup `<>` scans | `cartography/graph/cleanupbuilder.py:82,92,100` |
| AllNodesScan (gcp nic) | `cartography/intel/gcp/compute.py:1501` |
| AllNodesScan (azure vm) | `cartography/intel/azure/compute.py:989,999` |
| Full label scan (spanner) | `cartography/intel/gcp/spanner.py:157` |
| Cartesian linking (route53) | `cartography/intel/aws/route53.py:119,128,137` |
</content>
