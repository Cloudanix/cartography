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

## Phase B — Convert loaders to batched writes (DONE)

Goal: cap the size of any single OCI write transaction and cut transaction count.

All loaders across the 10 OCI modules now write through `load_graph_data`
(500-row batches, managed write transactions with transient-error retry).
One commit per module:

| Module | Loaders converted | Commit |
|--------|-------------------|--------|
| storage.py | 8 (A1 fat) | `146f8bf` |
| oke.py | 3 (A1 fat) | `c1f4647` |
| compartment.py | 1 | `e16c8b3` |
| organizations.py | 1 | `2fd42be` |
| encryption.py | 2 | `bf3a50d` |
| monitoring.py | 3 | `da292d6` |
| audit_logging.py | 4 (incl. the crash site) | `55c4477` |
| iam.py | 6 | `36cfa4b` |
| compute.py | 7 | `317e482` |
| network.py | 10 + 2 subnet linkers | `61cf547` |

Left unconverted by design: single-record loaders (`load_cloud_guard`,
`load_audit_configuration`, `load_logging_configuration`), set-based linkers
keyed on `lastupdated` (storage `link_instances*`, audit `mark_unlogged_buckets`),
per-statement policy-reference loaders, and the graph-read queries that drive
the syncs. Every converted loader has an integration test under
`tests/integration/cartography/intel/oci/`.

### Original plan


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

## Phase Indexes — MERGE/MATCH lookup coverage (DONE)

A `MERGE`/`MATCH` on a label+property with no matching index does a full label
scan — slower and more transaction state buffered.

- **`id` coverage: complete.** All 40 OCI node labels that appear in a
  `MERGE (x:Label{id:...})` already have an `id` index in `indexes.cypher`.
  No gaps.
- **Non-`id` MATCH coverage: 4 gaps found and fixed.** The relationship-
  resolution MATCHes that key on a non-`id` field had no supporting index, so
  each linking loader full-scanned its label per batch. Added (commit with the
  Phase B docs update):
  - `OCIVnicAttachment(vnic_id)` — network `load_vnics`
  - `OCIBootVolumeAttachment(boot_volume_id)` — compute `load_boot_volumes`
  - `OCIVolumeAttachment(volume_id)` — compute `load_block_volumes`
  - `OCIMountTarget(export_set_id)` — storage `load_exports`
- Future: consider upgrading hot labels from plain index to a uniqueness
  constraint (adds dedupe + locking) where a label's `id` is guaranteed unique.

## Execution rules

- One commit per change. Validate with tests before each commit.
- Recommend shipping options **1 + 2** (orchestration/config) immediately to stop
  the bleeding; they are outside this repo (Pub/Sub + Neo4j config) but are the
  fastest mitigation.
