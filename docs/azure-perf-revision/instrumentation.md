# Phase 1 — Instrumentation

## What Was Changed

`cartography/intel/azure/__init__.py` was modified in two functions. Behavior is unchanged — the same services and analysis jobs run in the same order.

### Per-service timing (`_sync_one_subscription`, line 80)

Each call into `RESOURCE_FUNCTIONS` is wrapped with `time.time()` in the EKS/local sequential path. After every service completes, one JSON line is emitted:

```json
{
  "event": "azure_service_timing",
  "subscription_id": "<sub-id>",
  "service": "compute",
  "duration_seconds": 47.3
}
```

After the full loop, a summary line is emitted:

```json
{
  "event": "azure_subscription_timing_summary",
  "subscription_id": "<sub-id>",
  "total_duration_seconds": 312.8,
  "service_timings": {
    "iam": 18.2,
    "network": 91.4,
    "compute": 47.3,
    "..."
  },
  "slowest_service": "network"
}
```

### Per-analysis-job timing (`_sync_multiple_subscriptions`, line 216)

The 9 Cypher analysis jobs were refactored from 9 separate `run_analysis_job()` calls into a single `_analysis_jobs` list iterated in a loop. Each job is timed individually:

```json
{
  "event": "azure_analysis_jobs_timing",
  "subscription_id": "<sub-id>",
  "total_duration_seconds": 28.1,
  "job_timings": {
    "azure_network_security_group_asset_exposure.json": 6.2,
    "azure_vm_asset_exposure.json": 4.8,
    "..."
  }
}
```

## How to Verify Instrumentation is Active

The timing lines are emitted at `INFO` level. The container must have `CDX_LOG_LEVEL=INFO` (or lower) set for them to appear. In `scripts/azure.env.prod.yml`, change:

```yaml
CDX_LOG_LEVEL: INFO
```

Then rebuild and redeploy. On the next job run, grep the pod logs:

```bash
kubectl logs <pod-name> | grep azure_service_timing
kubectl logs <pod-name> | grep azure_subscription_timing_summary
kubectl logs <pod-name> | grep azure_analysis_jobs_timing
```

## Overhead

Each timing checkpoint is two `time.time()` calls and one `json.dumps` + `logger.info`. This adds microseconds per service — negligible against multi-second sync operations.
