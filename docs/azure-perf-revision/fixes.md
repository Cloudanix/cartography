# Phase 3 — Fixes

Apply the fix that matches your analysis findings. Each fix is independent — apply only what the data supports.

---

## Fix A: Enable Parallel Execution in EKS

**Apply when**: All services are slow and the subscription has many resources. The Lambda path already runs services in parallel via `ThreadPoolExecutor`; the EKS path forces sequential execution.

**Location**: `cartography/intel/azure/__init__.py`, line 77 (`_sync_one_subscription`)

**Current condition**:
```python
if os.environ.get("LOCAL_RUN", "0") == "1" or os.environ.get("CDX_RUN_AS") == "EKS":
    # BEGIN - Sequential Run
```

**Change to**:
```python
if os.environ.get("LOCAL_RUN", "0") == "1":
    # BEGIN - Sequential Run (local dev only)
```

This makes the `else` branch — the `ThreadPoolExecutor` path (line 125) — run in EKS as well.

**How it works**: The `concurrent_execution` function (line 33) already opens its own Neo4j driver per service, so services don't share a session. The 12 service modules are independent of each other; `tag.sync` is pinned to run last (line 156), outside both branches.

**Expected gain**: Total time drops from `sum(service_times)` to approximately `max(service_times)`.

**Risk**: If any service mutates `common_job_parameters` in a way that another service depends on, there will be a race condition. Audit `RESOURCE_FUNCTIONS` values before enabling. As of the current codebase, services only read `common_job_parameters` — writes to it happen in the orchestration layer, not inside sync functions.

---

## Fix B: Slow Individual Service

**Apply when**: One specific service (e.g. `network`, `compute`) accounts for a disproportionate share of time.

The typical root cause is a full unbounded list call against the Azure API returning thousands of resources with no page size limit.

### Step 1 — Find the list calls

```bash
grep -n "list_all\|list\|get_all" cartography/intel/azure/<service>.py | head -30
```

### Step 2 — Add a page size where the SDK supports it

Azure SDK list methods that accept `top=` or `maxresults=`:

```python
# Before
results = client.virtual_machines.list(resource_group)

# After — cap at 1000 per page, let the SDK paginate
results = client.virtual_machines.list(resource_group, top=1000)
```

### Step 3 — Stream results instead of collecting them

If the sync function materialises the full API response into a list before writing to Neo4j, change it to stream:

```python
# Before (materialises entire response in memory)
vms = list(client.virtual_machines.list_all())
load_vms(neo4j_session, vms, ...)

# After (yields batches)
BATCH_SIZE = 500
batch = []
for vm in client.virtual_machines.list_all():
    batch.append(vm)
    if len(batch) >= BATCH_SIZE:
        load_vms(neo4j_session, batch, ...)
        batch.clear()
if batch:
    load_vms(neo4j_session, batch, ...)
```

---

## Fix C: Parallelize Analysis Jobs

**Apply when**: `azure_analysis_jobs_timing.total_duration_seconds` is a significant fraction of overall time. The 9 Cypher analysis jobs are independent of each other and can run concurrently.

**Location**: `cartography/intel/azure/__init__.py`, line 228 (`_sync_multiple_subscriptions`)

**Current code** (sequential loop over `_analysis_jobs`):
```python
for job_file in _analysis_jobs:
    t0 = time.time()
    run_analysis_job(job_file, neo4j_session, common_job_parameters)
    elapsed = round(time.time() - t0, 2)
    analysis_timings[job_file] = elapsed
```

**Replace with**:
```python
from neo4j import GraphDatabase

def _run_analysis_job_isolated(job_file, config, params):
    neo4j_auth = (config.neo4j_user, config.neo4j_password)
    driver = GraphDatabase.driver(
        config.neo4j_uri,
        auth=neo4j_auth,
        max_connection_lifetime=config.neo4j_max_connection_lifetime,
    )
    t0 = time.time()
    with driver.session() as session:
        run_analysis_job(job_file, session, params)
    return job_file, round(time.time() - t0, 2)

analysis_timings: Dict[str, float] = {}
with ThreadPoolExecutor(max_workers=4) as ex:
    futures = {
        ex.submit(_run_analysis_job_isolated, jf, config, common_job_parameters): jf
        for jf in _analysis_jobs
    }
    for future in as_completed(futures):
        job_file, elapsed = future.result()
        analysis_timings[job_file] = elapsed
```

`max_workers=4` is a safe starting point. Neo4j sessions are not thread-safe, so each job gets its own driver/session — the same pattern used by `concurrent_execution` for service syncs.

**Note**: `config` must be passed down into `_sync_multiple_subscriptions`. It is already passed to `_sync_one_subscription` — thread it through.

---

## Fix D: Batch Neo4j Writes

**Apply when**: Per-service drill-down shows `neo4j_write` time >> `fetch` time, meaning the Azure API is fast but Neo4j is slow to ingest.

The cause is usually individual `MERGE` statements executed one resource at a time inside a loop.

### Identify the pattern

```bash
grep -n "session.run\|neo4j_session.run" cartography/intel/azure/<service>.py | head -20
```

If `session.run(...)` appears inside a `for resource in resources:` loop, each resource opens a separate transaction round-trip.

### Fix: use UNWIND

```python
# Before — one Cypher round-trip per resource
for vm in vms:
    neo4j_session.run(
        "MERGE (v:AzureVirtualMachine {id: $id}) SET v.name = $name ...",
        id=vm['id'], name=vm['name'], ...
    )

# After — one round-trip for the entire batch
neo4j_session.run(
    """
    UNWIND $vms AS vm
    MERGE (v:AzureVirtualMachine {id: vm.id})
    SET v.name = vm.name, v.lastupdated = $update_tag
    """,
    vms=[{"id": v["id"], "name": v["name"]} for v in vms],
    update_tag=update_tag,
)
```

For very large resource sets, split into batches of 500–1000 to avoid exceeding Neo4j transaction memory limits.

---

## Fix E: Reduce Number of Subscriptions Processed Per Job

**Apply when**: A tenant has many subscriptions and each job processes all of them. Already supported by the `services` + pagination mechanism in `app.py` — ensure the caller sets `defaultSubscription` and `subscriptions` in the message payload to limit scope per job invocation.

---

## Applying Multiple Fixes

The fixes compose. A recommended order:

1. **Fix A** first — parallel execution requires no per-service code changes and gives the biggest return.
2. **Fix C** next — easy, analysis jobs are already isolated.
3. **Fix B** or **Fix D** for whichever service the data shows as the outlier after Fix A.

After each fix, redeploy and compare `azure_subscription_timing_summary.total_duration_seconds` against the baseline captured in Phase 2.
