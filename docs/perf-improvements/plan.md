# Neo4j Scaling — Performance Improvement Plan

Status: active · Owner: backend · Last updated: 2026-08-06

This plan analyzes the cartography codebase against four well-known Neo4j scaling
remediations and lays out concrete, prioritized work. Every finding below is
backed by a `file:line` reference. **All references re-verified 2026-08-06** against
`bug-fixes` (drifted line numbers corrected; resolved offenders struck through).

The four remediations:

1. Use the UNWIND pattern for batching
2. Use managed transactions
3. Ensure indexes exist for key fields
4. Use EXPLAIN/PROFILE to find inefficient APIs (AllNodesScan, etc.)

---

## TL;DR — what to fix, in order

| # | Fix | Why | Effort | Impact |
|---|-----|-----|--------|--------|
| 1 | ~~Add labels to label-less / unindexed `MATCH`es~~ | AllNodesScan on every run | S | ✅ **shipped (Phase 1)** |
| 2 | ~~Index non-`id` loader `MATCH` properties (`GCPSpannerInstance.config`, `AzureCluster.name`)~~ | Full label scan per batch | S | ✅ **shipped (Phase 1)** |
| 3 | Migrate hand-written **per-item** loops to `load()` — `gcp/compute.py`, `aws/iam.py`, then `aws/redshift.py` + `aws/ec2/{load_balancers,load_balancer_v2s,security_groups}.py` | One round-trip per row instead of per 500-row batch | L | 🔴 High |
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
| 1 | Query/index fixes + `ensure_indexes` managed-tx wrap | ✅ done — unit + integration green in CI |
| 2 | Integration EXPLAIN plan guard (+ self-test) | ✅ done — unit + real-EXPLAIN sweep green in CI |
| 3.0 | Foundation: `session.py` silent-fail fix, `graph_write_seconds` split, upstream `tx.py` backport (batch 10k + retry + matchlinks), `ensure_indexes` memoize | ✅ done 2026-08-06 — unit tests green locally; integration pending CI |
| 3 | Batch per-item loaders + wrap already-UNWIND raw writes (re-scoped 2026-08-06) | ✅ done 2026-08-06 — unit tests green locally; integration + guard sweep pending CI |
| 4 | PROFILE unanchored cleanup queries | ⚪ not started — **next up** (after Phase 3 CI run) |

> **CI update (2026-08-06):** the integration suite has run for Phases 1 and 2. Every item
> previously marked ⏳ pending CI is green. The Phase 2 sweep is a hard gate
> (`KNOWN_OFFENDERS = set()`) and passed, so no generated schema currently plans an
> `AllNodesScan`. Phase 3 is therefore no longer blocked (decision 4); each migration must
> show zero `*Scan` on its new ingestion query before merge (decision 12A).

### Phase 1 checklist

| # | Change | Test | Unit/lint here | Integration (CI) | Commit |
|---|--------|------|----------------|------------------|--------|
| 1.1 | `ensure_indexes` raw `run` → `execute_write` (`tx.py:234`) | unit (mock session) | ✅ 3 pass | n/a | ✅ |
| 1.2 | `gcp/compute.py:1501` `MATCH (nic)` → `:GCPNetworkInterface` | existing `test_compute.py:346` | flake8 ✅ | ✅ green | ✅ |
| 1.3 | `gcp/spanner.py:157` + index `GCPSpannerInstance(config)` | existing `test_spanner.py` | n/a | ✅ green | ✅ |
| 1.4 | `azure/compute.py` AKS per-label queries + `AzureCluster(name,resourcegroup)` index | new red-first `test_aks.py::test_link_compute_to_aks` (9A) | flake8 ✅ (net −1 E501), compile ✅ | ✅ green | ✅ |

> **1.4 note:** Cypher forbids `UNION` around write clauses, so decision 7A's "templated UNION"
> is realized as a template run once per label (same DRY win, valid Cypher). Azure modules can't
> be imported in the dev sandbox (missing `cloudconsolelink`), so the rewrite was validated by the
> new integration test in CI — now green. Locally confirmed via flake8 + byte-compile + `.format`
> render check.

> **Validation note:** neo4j/docker is unavailable in the dev sandbox, so integration tests were
> unit-validated + linted locally and run via `make test_integration` in CI. That CI run has since
> completed — all Phase 1 integration tests pass.

### Phase 2 checklist — EXPLAIN plan guard

| # | Item | Decision | Status |
|---|------|----------|--------|
| 2.1 | Pure plan-walk + banned-operator detection (`plan_guard.py`) | 1A | ✅ unit 5/5 |
| 2.2 | Enumerate all generated ingestion + cleanup queries | 13A | ✅ unit (37 schemas, all build) |
| 2.3 | Guard self-test: label-less fails, indexed passes | 10A | ✅ unit fixtures + real-EXPLAIN fixtures green in CI |
| 2.4 | Sweep all generated queries via real EXPLAIN, fail on `AllNodesScan` | 13A | ✅ green in CI (`test_query_plans.py`), 0 offenders |

> **Phase 2 notes:**
> - Detection logic is neo4j-free (`tests/integration/.../graph/plan_guard.py`) so it unit-tests
>   without a database; the integration test only adds real `EXPLAIN` execution.
> - `BANNED_OPERATORS = {AllNodesScan}` only. `NodeByLabelScan` is **not** banned — a bounded
>   label scan (anchored cleanup) is fine (consistent with the Phase 4 correction).
> - `ensure_indexes(schema)` runs before each EXPLAIN so the plan reflects production indexes
>   (decisions 1A/12A). Per-schema row seeding is skipped — index presence, not row count, is
>   what flips `AllNodesScan`→`NodeIndexSeek` for these `MERGE`-on-id queries.
> - The sweep is a **hard gate** (`KNOWN_OFFENDERS = set()`). If CI surfaces an existing schema
>   that plans `AllNodesScan`, triage it (fix the query, or allowlist with a TODO) — that is the
>   guard doing its job (decisions 6A/12A).
> - **Migrate-OOM gate (12A):** Phase 3 migrations run this sweep on the new ingestion query and
>   must show zero `*Scan` before merge — prevents reproducing CDX-INVENTORY-887.


### Phase 3 — what it actually is, in plain English

**The problem.** For resources that were never migrated to the schema/`load()` path,
cartography writes one row per network round-trip:

```python
for user in users:                       # e.g. 5,000 IAM users
    neo4j_session.run(query, ...)        # 5,000 round-trips, 5,000 transactions
```

**The fix.** Describe the node once as a `CartographyNodeSchema`, then delete the loop:

```python
load(neo4j_session, IAMUserSchema(), users)   # 10 round-trips (500 rows each)
```

That single swap buys all three remediations at once, because `load()`
(`cartography/client/core/tx.py:252`) already does them:

| You get | From | Fixes |
|---|---|---|
| UNWIND batching, 500 rows/tx | `load_graph_data` (`tx.py:208`, batch at `:223`) | §1 |
| Managed tx + `TransientError` retry | `session.execute_write` inside the batch loop | §2 |
| Auto-created indexes for `id`, `lastupdated`, rel-target and `extra_index` fields | `ensure_indexes` (`tx.py:232`) → `build_create_index_queries` (`querybuilder.py:402`) | §3 |

**The cost.** Per module: write the schema dataclass, replace the loop, keep behaviour
identical. The module's existing integration test is the correctness check; the Phase 2
EXPLAIN guard is the performance check (zero `*Scan` on the new ingestion query before
merge — decision 12A). Copy any OCI module, e.g. `cartography/intel/oci/compute.py`.

**Nothing is rewritten from scratch** — this is applying an existing, tested path to
modules that predate it.

### Phase 3 re-scope (2026-08-06)

The original target list ("GCP compute, AWS iam/rds, Azure write-heavy modules") ranked
modules by **count of raw `session.run()` calls**. That is the wrong metric: a raw
`run()` whose query already says `UNWIND $DictList AS item` is *already batched* — it
only lacks managed-tx retry, which is a §2 one-liner, not a §1 migration.

Re-measured by AST scan (count `.run()` calls lexically inside a `for` loop = true
per-item writes; count `UNWIND` occurrences = already-batched queries):

| Module | raw `run()` | **inside a `for`** | uses `UNWIND` | Verdict |
|---|---:|---:|---:|---|
| `gcp/compute.py` | 23 | **11** | 7 | 🔴 P1 — worst offender |
| `aws/iam.py` | 20 | **10** | 2 | 🔴 P1 |
| `aws/redshift.py` | 7 | **5** | 3 | 🟠 P2 |
| `aws/ec2/load_balancers.py` | 6 | **5** | 1 | 🟠 P2 |
| `aws/ec2/security_groups.py` | 6 | **5** | 0 | 🟠 P2 |
| `aws/ec2/load_balancer_v2s.py` | 5 | **4** | 1 | 🟠 P2 |
| `github/repos.py` | 6 | 2 | 5 | 🟢 P3 |
| `aws/rds.py` | 16 | 2 | 14 | 🟢 P3 |
| `azure/subscription.py` | 1 | 1 | 0 | 🟢 P3 — trivial |
| `digitalocean/compute.py` | 1 | 1 | 0 | 🟢 P3 — trivial |
| `azure/sql.py` | 29 | 1 | 14 | ⚪ §2 only |
| `aws/s3.py` | 10 | 1 | 7 | ⚪ §2 only |
| `aws/route53.py` | 12 | 1 | 7 | ⚪ §2 only |
| `azure/cosmosdb.py` | 22 | 0 | 16 | ⚪ §2 only |
| `azure/storage.py` | 18 | 0 | 9 | ⚪ §2 only |
| `gcp/spanner.py` | 5 | 0 | 5 | ⚪ §2 only |
| `pagerduty/services.py` | 3 | 0 | 3 | ⚪ §2 only |

**Corrections this forces:**

- **Azure is not a Phase 3 target — but it is not clean either.** `cosmosdb.py`
  (0 per-item), `storage.py` (0) and `sql.py` (1) already UNWIND, so the §1 per-row
  problem Phase 3 exists to solve is absent; a schema migration would be re-plumbing, not
  a speedup. Two real defects remain, both cheaper than migration:
  1. **No retry** — raw `run()` is auto-commit (§2). Wrap in `execute_write`. Effort S.
  2. **No 500-row chunk** — the whole list goes in one transaction, unlike
     `load_graph_data` (`tx.py:223`). A large account can blow
     `dbms.memory.transaction.total.max` — the CDX-INVENTORY-887 failure mode.
  Same shape for `aws/s3.py`, `aws/route53.py`, `gcp/spanner.py`, `pagerduty/services.py`.
- **Azure's UNWIND is per-parent, not global.** e.g. `cosmosdb.py:173` loops accounts and
  calls `_load_database_account_write_locations` per account (`:263`), so round-trips scale
  with **parent count**, not row count. Middle tier: better than per-row, worse than
  `load()`. Fixing it is Phase 3.7, not a migration.
- **`aws/rds.py` drops out of P1.** 14 of its 16 queries already UNWIND; only 2 per-item
  writes remain.
- **AWS ELB/SG modules move up.** `aws/ec2/load_balancers.py`, `load_balancer_v2s.py` and
  `security_groups.py` are almost entirely per-item and are small files (≤257 LOC) — the
  cheapest real wins after the two P1s. Note the old plan's paths `aws/load_balancers.py` /
  `aws/load_balancer_v2s.py` no longer exist; both live under `aws/ec2/`.
- **`gcp/compute.py` is worse than a flat count suggests** — some writes are *nested*
  loops, e.g. `_attach_gcp_vpc_tags` (`gcp/compute.py:1427`) runs one query per
  `instance × tag × network-interface`, so round-trips grow multiplicatively, not linearly.

### Phase 3.0 checklist — foundation (do first)

Implements the **Recommended order** step 1 (strategic Options 2 + 5 + the `session.py`
fix — see Strategic options section). Blocks 3.1+: migrations cannot be verified while
writes fail silently, and the `tx.py` backport changes the target they migrate onto.

| # | Task | Scope / key files | Est. | Status |
|---|------|-------------------|------|--------|
| 3.0.1 | Fix silent exception swallowing — every wrapper that logs + `return self` must re-raise (or retry, then raise): `run()`, `execute_write()`, `execute_read()` | `cartography/graph/session.py` | S | ✅ `92d62da40`, `bc0693378` |
| 3.0.2 | Split graph-write time from API time: emit `graph_write_seconds` alongside `duration_seconds`; then re-rank remaining work with real numbers | `graph/write_timer.py` (new), `graph/session.py`, azure `util/timing.py`, aws/gcp `__init__.py` | S | ✅ `8efe6aec0`, `8d66b5960`, `52e8278ff` |
| 3.0.3 | Backport upstream `client/core/tx.py`: `batch_size=10000` tunable per call (supersedes decision 14A), retry classification (network, `TransientError`, `BufferError`, `EntityNotFound`), empty-input short-circuit, index-race tolerance | `cartography/client/core/tx.py` | M | ✅ `e1f90f7ca`, `50453c34b`, `82b166502`, `f649917d9` |
| 3.0.4 | Backport `load_matchlinks()` + `build_matchlink_query()` — relationship-only loader; migration target for hand-written linkers (AKS, route53) | `models/core/relationships.py`, `querybuilder.py`, `tx.py` | S | ✅ `1fc2e87ec`, `acfa2eb89`, `fd3f314dc` |
| 3.0.5 | Memoize `ensure_indexes()` per process (Option 5) | `tx.py` | XS | ✅ `e52b15207` |

> **3.0.1 scope note (2026-08-06):** `session.py` had gained a `TransientError`
> retry loop, but the retry returned `self` on exhaustion instead of raising,
> non-transient exceptions were still swallowed, and the `execute_write`/
> `execute_read` wrappers swallowed too. All of them now log and **raise**.

> **Phase 3.0 implementation notes (2026-08-06):** all tasks landed with unit tests
> (`test_session.py`, `test_write_timer.py`, `test_tx.py`, `test_querybuilder_matchlink.py`,
> `test_relationships.py`, `test_timing.py`) — 60+ new assertions, one atomic commit per
> change. New helpers for Phase 3.7: `run_write_query()` (drop-in for raw auto-commit
> `session.run`) and `execute_write_with_retry()`. The matchlink backport is the minimal
> core: upstream's optional sub-resource-scoped endpoint matching is deferred until a
> call site needs it. Run integration in CI before starting 3.1 (sandbox has no neo4j;
> `test_plan_guard.py::test_iter_generated_queries_builds_all` has a pre-existing,
> ordering-dependent failure when run with the querybuilder-excs test module — verified
> present before these changes at `7f4bcddd8`).

### Phase 3 checklist

Prereq: **Phase 3.0 complete.** Chain-migrate whole dependency chains atomically
(decisions 4, 8). Guard sweep green before each merge (12A). Use upstream's schema
definitions as donor code where the fork has no custom logic (Option 3, selectively).

| # | Module | Per-item writes | Est. | Status |
|---|--------|----------------:|------|--------|
| 3.1 | `gcp/compute.py` (instance/NIC/subnet/VPC/tag chain) | 11 (incl. nested) | L | ✅ `2d318fc17`..`37dfbfb07` (5 commits) |
| 3.2 | `aws/iam.py` (user/group/role/policy/access-key chain) | 10 | L | ✅ `b6bdc8cf2`, `1abf8046e`, `dc8bf7393` |
| 3.3 | `aws/ec2/security_groups.py` | 5 | S | ✅ `38fda6601` |
| 3.4 | `aws/ec2/load_balancers.py` + `load_balancer_v2s.py` | 9 | M | ✅ `64cf92c2b`, `1da1d1ad1` |
| 3.5 | `aws/redshift.py` | 5 | S | ✅ `dcfeb5caa` |
| 3.6 | `github/repos.py`, `aws/rds.py`, `azure/subscription.py`, `digitalocean/compute.py` | 1–2 each | S | ✅ `dcd217064` |
| 3.7 | Already-UNWIND raw writes → `load_graph_data` (10k chunks + retry) / `run_write_query` (azure ×3, aws s3/route53, gcp spanner, pagerduty) | n/a | M | ✅ `3f637d91c`, `affa89d32`, `05de80069` |

> **Phase 3 implementation notes (2026-08-06):** executed via the plan §1.3 "intermediate
> win": each per-item loop rewritten as one UNWIND batch through `load_graph_data`
> (managed tx, retry, 10k-row chunks), preserving query text, labels, and consolelink
> props — not full schema migrations (those remain available selectively via upstream
> donors). Public loader signatures used by integration tests are preserved. ~30 new
> unit tests over row builders and write batching; the full unit suite shows zero new
> failures vs the pre-Phase-3 baseline (one pre-existing failure fixed:
> `test_principal_policies`). Integration suite + Phase 2 guard sweep must run in CI
> before Phase 4.

---

## How data flows today (baseline)

The modern, efficient path already exists and is the migration target:

```
intel module
  └─ tx.load(session, node_schema, dict_list)            cartography/client/core/tx.py:252
        ├─ ensure_indexes(session, node_schema)           tx.py:232  → auto CREATE INDEX
        └─ load_graph_data(session, query, dict_list)     tx.py:208
              └─ for batch in batch(dict_list, size=500): tx.py:223
                    session.execute_write(write_list_of_dicts_tx, query, DictList=batch)
```

- `build_ingestion_query()` (`cartography/graph/querybuilder.py:347`) generates a single
  `UNWIND $DictList AS item MERGE (...) SET ...` query — correct batched pattern.
- `build_create_index_queries()` (`querybuilder.py:402`) auto-creates indexes for the
  node's `id`, `lastupdated`, every relationship `TargetNodeMatcher` field, and any
  `PropertyRef(extra_index=True)`.
- Static baseline indexes live in `cartography/data/indexes.cypher` (494 `CREATE INDEX`
  statements), applied once before sync via `cartography/intel/create_indexes.py`.

**Coverage as of 2026-08-06 (AST scan over `cartography/intel`, 223 files):**

| Provider | files | use `load()` | raw `session.run()` | of which per-item |
|---|---:|---:|---:|---:|
| aws | 61 | 10 | 148 | 40 |
| azure | 22 | **0** | 82 | 4 |
| gcp | 34 | **0** | 42 | 16 |
| oci | 18 | 10 | 28 | 6 |
| pagerduty | 7 | 0 | 17 | 0 |
| okta | 11 | 0 | 15 | 0 |
| github | 7 | 1 | 8 | 2 |
| duo | 8 | 7 | 0 | 0 |
| *(others)* | 35 | 3 | 31 | 3 |
| **TOTAL** | **223** | **31** | **371** | **71** |

So **~14% of intel files** use the managed, chunked `load()` path. The other 371 raw
`run()` calls fall into three tiers, and only the first is a Phase 3 migration:

1. **Per-item (71 calls)** — one round-trip *per row*. §1 + §2 + §3 all broken. → Phase 3.1–3.6.
2. **UNWIND, per-parent, unchunked (~300 calls)** — batched, but auto-commit (no retry)
   and no 500-row cap. → Phase 3.7, effort S–M each.
3. **Reads** — `run()` used to query, not write. Should use `execute_read` (§2 note).

GCP and Azure have **zero** migrated modules; AWS is 10/61.

---

## 1. UNWIND batching

### What's good
- `load_graph_data()` batches at **500 rows/transaction** via UNWIND — the right pattern.
- All OCI modules use it. The querybuilder makes it the default for new code.

### Gaps — per-item loops (one transaction per row)
These are the scaling bottleneck: a Python `for` loop calling `session.run()` once per
item means N network round-trips and N transactions instead of `ceil(N/500)`.

Measured per module in the **Phase 3 re-scope** table above. Headline:

- **GCP compute** — 11 per-item writes across the VPC / subnet / NIC / access-config /
  service-account / firewall loaders, and `_attach_gcp_vpc_tags` (`gcp/compute.py:1427`)
  is a *nested* loop (one query per instance × tag × NIC). Top migration target.
- **AWS IAM** — 10 per-item writes: one per user (`iam.py:494`), group (`:651`),
  role (`:735`), external principal (`:756`), trust-policy principal (`:766`),
  group membership (`:794`), access key (`:904`).
- **AWS ELB / security groups** — `aws/ec2/{load_balancers,load_balancer_v2s,security_groups}.py`
  are almost entirely per-item, but small; cheap wins.
- **Azure and most other write-heavy modules already UNWIND** — they need §2 (managed-tx
  wrapping), not a §1 migration. See the re-scope table.

### Plan
1. Rank by **measured per-item write count**, not raw `run()` count — see the Phase 3
   re-scope table. Order: `gcp/compute.py` → `aws/iam.py` → AWS ELB/SG/redshift → misc.
2. For each: define a `CartographyNodeSchema` (if missing) and replace the
   hand-written loop with `tx.load(...)`. This gets UNWIND batching, managed
   transactions, and auto-indexes in one move.
3. Where a full schema migration is too large, intermediate win: rewrite the loop
   body as a single `UNWIND $DictList AS item ...` query and call `load_graph_data()`
   directly with the existing query string.
4. Coverage is tracked in the **Phase 3 checklist** above (one row per module/chain).

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
writes: `azure/sql.py` (29), `azure/cosmosdb.py` (22), `azure/storage.py` (18),
`gcp/compute.py` (23), `aws/iam.py` (20). Note the Azure three are **already UNWIND-batched**
— for them this is the only defect, so they are cheap `execute_write` wraps (Phase 3.7),
not migrations.

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
3. ✅ **Systematic:** done differently — decision 6A rejected a static Cypher lint as
   brittle. The Phase 2 EXPLAIN guard enforces the same rule empirically: an unindexed
   non-`id` `MATCH` shows up as `AllNodesScan` in the plan and fails CI.

---

## 4. EXPLAIN / inefficient APIs (AllNodesScan)

### Confirmed offenders

All three AllNodesScan/full-scan sites below were **fixed in Phase 1 and verified green in
CI** (2026-08-06); line numbers updated to their post-fix locations.

- ~~**AllNodesScan — label-less `MATCH`:**~~ ✅ fixed
  - `cartography/intel/gcp/compute.py:1504` — now `MATCH (nic:GCPNetworkInterface{id: $NicId})`.
  - `cartography/intel/azure/compute.py:998,1008` — now
    `MATCH (c:AzureCluster {name: ..., resourcegroup: ...})`, one templated query per label.
- ~~**Full label scan on non-indexed property:**~~ ✅ fixed — `gcp/spanner.py:157` still
  matches on `config`, but `GCPSpannerInstance(config)` is now indexed.
- **Cartesian-style linking (still open):** `cartography/intel/aws/route53.py:119,128,137` —
  `MATCH (n:AWSDNSRecord) WITH n MATCH (l:LoadBalancer{dnsname: n.value})`. The target
  match keys on `dnsname`; confirm those are indexed and that the planner isn't doing an
  n×m join. Rewrite as a single UNWIND + indexed lookup if the plan is bad.
- **Cleanup scans:** `cartography/graph/cleanupbuilder.py:82,92,100` generate
  `WHERE n.lastupdated <> $UPDATE_TAG`. The *hand-written* job JSONs (247/261) anchor on
  indexed ids before this filter (bounded subgraph — fine). The *generated* cleanupbuilder
  queries are the ones to PROFILE: confirm they anchor via the sub-resource relationship
  (which is indexed) rather than starting from a bare `MATCH (n:Label)`. Do **not** rewrite
  `<>`→`=` (different semantics).

### Instrumentation
~~There is zero use of `EXPLAIN`/`PROFILE` in code or tests.~~ Shipped in Phase 2:
`tests/integration/cartography/graph/test_query_plans.py` + `plan_guard.py` run real
`EXPLAIN` over every generated ingestion/cleanup query and fail on `AllNodesScan`.
`PROFILE` is still unused — that is Phase 4.

### Plan
1. ✅ Fix the three confirmed AllNodesScan/full-scan sites above (Phase 1).
2. ✅ Add a **plan-guard test** (Phase 2): a unit/integration test that runs `EXPLAIN <query>` against
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

**Phase 1 — quick, high-value (days):** ✅ done
- Fixed label-less/unindexed MATCHes in `gcp/compute.py`, `azure/compute.py`,
  `gcp/spanner.py` (+ index); wrapped `ensure_indexes()` in `execute_write`.

**Phase 2 — guardrails (days):** ✅ done
- EXPLAIN plan-guard test over querybuilder + cleanupbuilder outputs.
- Index-coverage enforced by the guard (decision 6A — no separate static lint).

**Phase 3.0 — foundation (days):** ⚪ next up
- Fix `session.py` swallowed exceptions (all wrappers) — prerequisite: migrations cannot
  be verified while writes fail silently.
- Add `graph_write_seconds` timing split; re-rank remaining work with real numbers.
- Backport upstream `tx.py` (batch 10k tunable, retry classification, `load_matchlinks`,
  empty short-circuit); memoize `ensure_indexes()`. Tracked in the **Phase 3.0 checklist**.

**Phase 3 — migration (incremental, weeks):** ⚪ after 3.0
- Migrate **per-item** loaders to `tx.load()`, ranked by measured per-item write count:
  `gcp/compute.py` → `aws/iam.py` → AWS ELB/SG/redshift → misc, taking upstream's schema
  definitions as the starting point where the fork has no custom logic (Option 3,
  selectively). Then wrap the already-batched raw writes (Azure, s3, route53, spanner,
  pagerduty) in `execute_write` (3.7). Each migration removes raw writes (§2) and gains
  UNWIND batching (§1) + auto-indexes (§3) at once. Full ranking and checklist:
  **Phase 3 re-scope** section above.

**Phase 4 — cleanup-scan optimization (narrowed, after measurement):**
- PROFILE only the generated `cleanupbuilder.py` queries + any unanchored hand-written job.
  Do not touch the 247 anchored jobs. (See TODOS.md "unanchored-cleanup audit".)

---

## Strategic options — what to do from here (2026-08-06)

Question asked: *what is the best-performing ingestion path, even if it means a large
codebase change?* Answered by measuring the fork, then measuring what upstream
(`cartography-cncf/cartography`, tracked locally as `upstream/master`) actually does.

### Upstream comparison

Same AST scan run against `upstream/master` (`git ls-tree` + `git show`, no checkout):

| Metric | This fork | Upstream | Ratio |
|---|---:|---:|---|
| `cartography/intel` files | 223 | 738 | — |
| Files using `load()` | 31 (**14%**) | 582 (**79%**) | 5.6× |
| Raw `session.run()` calls | 371 | 44 | 8.4× |
| **Per-item writes (`run()` in a `for`)** | **71** | **2** | **35×** |
| `load_matchlinks()` call sites | 0 | 87 | — |
| `data/indexes.cypher` `CREATE INDEX` | 494 | 35 | 14× |
| Default batch size | 500 (`load_graph_data`) | **10,000**, per-call tunable | 20× |

Per provider:

| Provider | Fork: files / `load()` / per-item | Upstream: files / `load()` / per-item |
|---|---|---|
| aws | 61 / 10 / **40** | 93 / 82 / **0** |
| azure | 22 / **0** / 4 | 39 / 33 / **0** |
| gcp | 34 / **0** / 16 | (no raw writes remaining) |
| oci | 18 / 10 / 6 | — |

**Conclusion: upstream already completed this plan's Phase 3.** The fork branched before
that work landed and diverged. Phase 3 is not novel engineering — it is catching up to a
migration that exists, is tested, and is running in production elsewhere.

### What upstream does that the fork does not

1. **`batch_size=10000`, tunable per call** (`tx.py` `load`/`load_graph_data`). The fork
   hardcodes 500 (`tx.py:223`); `util.DEFAULT_BATCH_SIZE` is 1000 and unused by the load
   path. 20× fewer commits for the same rows. Decision 14A ("leave 500") was made without
   knowing upstream ships 10,000 by default — **that decision should be revisited**.
2. **Real retry classification** (`_run_with_retry`, `execute_write_with_retry`). Retries
   network errors, `TransientError`, `BufferError("cannot be re-sized")`, and — critically —
   `Neo.ClientError.Statement.EntityNotFound`, which upstream documents as expected when
   *"multiple providers sync concurrently"* and *"large batch sizes are used"*.
3. **`load_matchlinks()` + `build_matchlink_query()`** — a relationship-only loader
   (`MATCH from`, `MATCH to`, `MERGE rel`) for links that cannot be expressed as part of a
   node load. 87 call sites upstream. This is the supported answer to every hand-written
   "link A to B" query in the fork (e.g. the AKS and route53 linkers).
4. **Indexes live in schemas, not a static file.** Upstream `indexes.cypher` is down to 35
   entries; the fork's is 494 and growing. Every entry there is an index the querybuilder
   cannot see, verify, or drop.
5. **Empty-input short-circuit** (`if len(dict_list) == 0: return`) and per-label load
   metrics (`stat_handler.incr(f"node.{label}.loaded")`). The fork has neither.

### Where the fork is ahead of upstream

- **Service-level write concurrency.** The fork runs providers' services in a
  `ThreadPoolExecutor` (aws/gcp/azure/github/bitbucket `__init__.py`, 8 workers) with a
  shared driver and `Session(neo4j_driver)` per worker. Upstream syncs on a single session
  (`sync.py:281`). This is a genuine fork advantage — **and it is exactly the condition
  upstream's `EntityNotFound` retry was written for.**
- **Structured JSON timing logs** per service/subscription.
- **EXPLAIN plan guard** (Phase 2) — upstream has no equivalent.

### ⚠️ Correctness defect found during this analysis — ✅ FIXED 2026-08-06 (3.0.1)

`cartography/graph/session.py:67` — the fork's `Session.run()` wrapper catches
`Exception`, logs a warning, and **returns `self`**:

```python
except Exception as e:
    logger.warning(f"Failed run neo4j cypher query. Error - {e}", ...)
    return self
```

Every one of the 371 raw `run()` writes therefore fails **silently**: the sync reports
success while rows are missing from the graph. Under the fork's 8-way write concurrency,
`EntityNotFound` is expected (upstream documents it) — and here it is swallowed rather
than retried. This is a bigger risk than any throughput number in this document and is
independent of which option below is chosen.

### The options

| # | Option | Change size | Expected perf | Risk | Verdict |
|---|---|---|---|---|---|
| 1 | Migrate the 71 per-item sites to `load()` (Phase 3 as written) | L (weeks) | **20–100× on those sites** | Med | Do — but not first |
| 2 | **Backport upstream `client/core/tx.py`** (batch 10k, retry classification, matchlinks, empty short-circuit) | **S–M (one file + call sites)** | 20× fewer commits on all migrated + future code; removes silent-failure class | Low | ✅ **Do first** |
| 3 | Converge fork modules onto upstream module code where the fork has no custom logic | XL | Same as 1, but reviewed and tested upstream | Med–High (merge conflicts, fork-specific fields e.g. `consolelink`) | Do selectively, per module |
| 4 | Chunk + wrap the ~300 UNWIND-per-parent raw writes (Phase 3.7) | M | Little throughput; removes OOM class | Low | Do alongside 1 |
| 5 | Memoize `ensure_indexes()` per process | XS | Removes ~6–8 round-trips per `load()` call per region per account | Very low | Free win, take it |
| 6 | Server-side batching via `apoc.periodic.iterate` (APOC is allowlisted in `docker-compose.yml:27`) | M | Saves only the per-batch RTT (~ms); commit cost dominates | Med (opaque to the EXPLAIN guard) | ❌ Reject |
| 7 | Raise write concurrency further (more workers / parallel batches per schema) | M | Bounded — every row's rel-attach locks the same sub-resource node | High (deadlocks) | ❌ Not until 2 lands |

### Recommended order

1. **Option 2 + 5 + the `session.py` fix** — days, not weeks. Biggest ratio of benefit to
   change size, and it makes everything after it safer and faster. Fixing the swallowed
   exception is a prerequisite: without it, migrations cannot be verified.
2. **Option 1**, module by module, taking upstream's schema definitions as the starting
   point wherever the fork has not customised the module (Option 3 applied selectively).
3. **Option 4** for the remaining already-UNWIND raw writes.

Status is tracked at task level in the **Phase 3.0 checklist** (foundation) and the
**Phase 3 checklist** (migrations) above — update those tables as code lands.

### The measurement gap that ranks 1 vs 2

The timing instrumentation (`docs/azure-timing-instrumentation.md`) records
`duration_seconds` for a whole service sync — cloud API fetch **plus** transform **plus**
graph write — with no split. `request_count` and `throttle_count` are recorded, so API
pressure is visible, but **graph-write time is not separable from API time today**.

Until that split exists, no one can say what fraction of sync wall-clock these options
actually address. Adding it is ~a day using the existing `ServiceTimingContext`: wrap the
load calls and emit `graph_write_seconds` alongside `duration_seconds`. Do it as part of
Option 2, then re-rank with real numbers.

---

## What already exists (reused, not rebuilt)

| Sub-problem | Existing code reused | Verdict |
|---|---|---|
| UNWIND batching | `load_graph_data` (`tx.py:208`, batch=500) | Reuse — migration target |
| Managed tx + retry | `execute_write`/`execute_read`, `GraphJob`/`GraphStatement` | Reuse |
| Index auto-gen | `build_create_index_queries` (`querybuilder.py:402`) | Reuse |
| Static index baseline | `data/indexes.cypher` (494 indexes) | Reuse |
| Migration recipe | OCI modules (`intel/oci/*`), Duo, migrated AWS modules | Copy pattern |
| Bad-plan detection | `tests/integration/.../graph/plan_guard.py` (Phase 2) | Reuse as merge gate |
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
| Phase 3 mass migration (now) | Was deferred until Phase 2 guardrails landed (decision 4); guard green in CI as of 2026-08-06, so Phase 3 is now in scope → TODOS.md |

---

## Verification

For every change, capture before/after `PROFILE` of the affected query (db hits, rows,
operators) on a representative dataset. The Phase 2 plan-guard test (green in CI since
2026-08-06) then prevents regressions. Migrations are behavior-preserving — existing
module integration tests must stay green, and the guard sweep must show zero `*Scan` on
the new ingestion query before merge (decision 12A).

**How the Phase 3 re-scope numbers were produced:** AST scan over each intel module —
count `.run()` calls lexically nested inside a `for`/`async for` (true per-item writes)
and count `UNWIND` occurrences in the module's query strings (already-batched queries).
Re-run it before starting a module; the counts move as migrations land.

## Key file reference

| Concern | File:line |
|---------|-----------|
| Batched load entrypoint | `cartography/client/core/tx.py` (`load`, `load_graph_data`; batch_size=10000 default, tunable) |
| Matchlink loader (3.0.4) | `tx.py` (`load_matchlinks`), `querybuilder.py` (`build_matchlink_query`) |
| Graph-write timing split | `cartography/graph/write_timer.py`, fed by `graph/session.py` |
| ~~Raw run in ensure_indexes~~ (now managed) | `cartography/client/core/tx.py:232` |
| Ingestion query (UNWIND) | `cartography/graph/querybuilder.py:347` |
| Auto index generation | `cartography/graph/querybuilder.py:402` |
| Static indexes | `cartography/data/indexes.cypher` (494 indexes) |
| Cleanup `<>` scans | `cartography/graph/cleanupbuilder.py:82,92,100` |
| EXPLAIN guard (Phase 2) | `tests/integration/cartography/graph/plan_guard.py`, `test_query_plans.py` |
| ✅ fixed — gcp nic label | `cartography/intel/gcp/compute.py:1504` |
| ✅ fixed — azure AKS labels | `cartography/intel/azure/compute.py:998,1008` |
| ✅ fixed — spanner config index | `cartography/intel/gcp/spanner.py:157` |
| Worst per-item loop (nested) | `cartography/intel/gcp/compute.py:1427` (`_attach_gcp_vpc_tags`) |
| Per-item IAM writes | `cartography/intel/aws/iam.py:494,651,735,756,766,794,904` |
| Cartesian linking (route53, open) | `cartography/intel/aws/route53.py:119,128,137` |
</content>
