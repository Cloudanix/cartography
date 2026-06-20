# OCI / Neo4j Transaction-Memory Optimization Plan

Tracking doc for reducing Neo4j transaction-memory pressure during OCI ingestion,
so we can stop hitting `dbms.memory.transaction.total.max` without raising the heap.

- Sentry: [CDX-CARTOGRAPHY-INVENTORY-887](https://cloudanix.sentry.io/issues/7563060236)
- Owner: backend / cartography
- Status: in progress

## Problem

Production raises:

```
TransientError: The allocation of an extra 2.0 MiB would use more than the limit
3.4 GiB. Currently using 3.4 GiB. dbms.memory.transaction.total.max threshold reached
```

The crashing frame (`audit_logging.load_logging_services`) runs a tiny per-row
`MERGE`. It is **not** the cause — it is the allocation that happened to touch the
ceiling.

### Why it happens

`dbms.memory.transaction.total.max` is the **aggregate cap across every in-flight
transaction on the whole DBMS**. It is a separate pool from JVM heap and page
cache. Hitting it means one of:

1. **Too many concurrent transactions** summing past the cap. The crash trace
   shows `ThreadPoolExecutor-0_1` under a Pub/Sub push handler — each Pub/Sub
   message is a separate cartography run, and all runs write the **same shared
   Neo4j**. Their open transactions add up. *(primary contributor)*
2. **Individual fat transactions** — a single `UNWIND $whole_list` or a
   non-iterative `DETACH DELETE` parks hundreds of MB in the pool for the whole
   duration of that statement. *(secondary contributor)*

Raising the cap (currently 3.4 GiB) only delays the next occurrence. The fixes
below cut the actual footprint.

## Options (by leverage)

### 1. Cap concurrency against each Neo4j — highest leverage, no code change
The pool is shared, so fewer simultaneous writers is the direct lever.
- Limit Pub/Sub subscription concurrency so only *K* cartography runs hit one
  Neo4j instance at a time. Pick *K* from `3.4 GiB / typical-run-peak`.
- Or a semaphore/queue in the push handler.
- Likely resolves the Sentry issue on its own. Phases below shrink per-run
  footprint so *K* can be raised safely.

### 2. Per-transaction cap — cheap blast-radius guard
```
db.memory.transaction.max=256m
```
One runaway transaction can no longer eat the entire 3.4 GiB pool. Does not add
capacity, but converts "whole DBMS wedged" into "one oversized query fails, rest
proceed", and surfaces the true offender instead of random bystanders.

### 3. Fix OCI write patterns — phases A/B below
### 4. Index coverage — phase Indexes below

## Phase A — Audit OCI write patterns (DONE)

Every OCI loader uses raw `neo4j_session.run()` — none go through the canonical
batched `cartography.client.core.tx.load_graph_data` (which chunks at 500). Two
patterns found:

### Pattern A1 — fat single transaction (HIGH risk for the OOM)
One `UNWIND $whole_list` = one transaction sized to the entire resource set. No
batching. These are the transactions that can individually grow large.

| Module | Loader / line | Notes |
|--------|---------------|-------|
| `storage.py` | `load_buckets` L213 | `UNWIND $buckets` |
| `storage.py` | `load_block_volumes` L359 / link L379 | `UNWIND $volumes` |
| `storage.py` | `load_boot_volumes` L517 / link L536 | `UNWIND $boot_volumes` |
| `storage.py` | `load_volume_backups` L701 + links L712/L723 | `UNWIND $backups` x3 over same list |
| `storage.py` | `load_file_systems` L925 / mount targets L961 / exports L992 / link L1020 | `UNWIND` over `$file_systems` / `$mount_targets` / `$exports` |
| `oke.py` | clusters L345 (`UNWIND $clusters`), pools L410 (`UNWIND $pools`), node links L436 (`UNWIND $links`, in loop) | |

### Pattern A2 — per-row loop (LOW memory each, but high tx churn + slow)
`neo4j_session.run()` once per resource inside a `for` loop → one autocommit
transaction per row. Memory-light individually, but many round-trips and, under
concurrency, more lock/transaction churn.

| Module | Per-row `run()` sites |
|--------|----------------------|
| `audit_logging.py` | L193, L244, L355, L532 |
| `compute.py` | L85, L155, L221, L287, L351, L475, L558 (7) |
| `network.py` | L76, L171, L269, L360, L471, L580, L671, L764, L844, L851, L926, L1068 (12) |
| `iam.py` | L111, L153, L225, L301, L331, L475 |
| `monitoring.py` | L80, L253, L344 |
| `encryption.py` | L76, L198 |
| `compartment.py` | L108 |
| `organizations.py` | L137 |

### Not a factor
- **No `DETACH DELETE` anywhere in OCI** — cleanup is not contributing here.

## Phase B — Convert loaders to batched writes

Goal: cap the size of any single OCI write transaction and cut transaction count.

- **A1 (fat) loaders first** — they are the ones that can grow large. Either
  migrate to `load_graph_data` (preferred, batches at 500) or wrap the existing
  `UNWIND` in `util.batch(list, size=500)` and run one transaction per chunk.
  For multi-pass loaders (`load_volume_backups` does node + 2 link passes over
  the same list), batch each pass.
- **A2 (per-row) loaders next** — migrate to a single batched `UNWIND` load
  (via `load_graph_data`) to collapse N autocommit transactions into
  `ceil(N/500)`. Lower priority for memory, real win for throughput.

Order within B:
1. `storage.py` (9 fat loaders) — biggest single-transaction risk.
2. `oke.py` (clusters/pools/links).
3. A2 modules: `network.py`, `compute.py`, `iam.py`, `audit_logging.py`,
   `monitoring.py`, `encryption.py`, `compartment.py`, `organizations.py`.

## Phase Indexes — MERGE lookup coverage

`indexes.cypher` has 40 OCI entries (plain `id` indexes). A `MERGE` on a label
with no matching index does a full label scan — slower and more transaction
state buffered.

- Audit: every OCI node label that appears in a `MERGE (x:Label{id:...})` must
  have a `CREATE INDEX ... FOR (n:Label) ON (n.id)` in `indexes.cypher`.
- Already covered: `OCIStorageBucket`, `OCIVolumeBackup`, `OCILoggingService`.
- Add any missing labels surfaced by the audit.
- Consider upgrading hot labels from plain index to a uniqueness constraint
  (adds dedupe + locking) where a label's `id` is guaranteed unique.

## Execution rules

- One commit per change. Validate with tests before each commit.
- Recommend shipping options **1 + 2** (orchestration/config) immediately to stop
  the bleeding; they are outside this repo (Pub/Sub + Neo4j config) but are the
  fastest mitigation.
