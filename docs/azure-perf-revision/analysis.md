# Phase 2 — Analyzing the Timing Data

After deploying the instrumented build and running at least one full sync, use the queries below to identify bottlenecks.

## From kubectl (live or recent pod)

```bash
# Replace <pod-name> with the actual job pod
kubectl logs <pod-name> \
  | grep -E '"event": "azure_subscription_timing_summary"' \
  | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get('event') != 'azure_subscription_timing_summary':
        continue
    timings = d.get('service_timings', {})
    total = d['total_duration_seconds']
    ranked = sorted(timings.items(), key=lambda x: x[1], reverse=True)
    print(f\"\nSubscription: {d['subscription_id']}  total={total}s\")
    for svc, t in ranked:
        pct = int(t / total * 40) if total else 0
        print(f'  {svc:25s}  {t:7.1f}s  {\"#\" * pct}')
"
```

Sample output:
```
Subscription: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  total=318.4s
  network                    91.4s  ############
  compute                    47.3s  ######
  storage                    38.2s  #####
  sql                        31.0s  ####
  iam                        18.2s  ##
  ...
```

## From CloudWatch Logs Insights

Navigate to **CloudWatch > Logs Insights** and select the EKS log group (e.g. `/eks/azure-graph-service`).

### Rank services across all recent runs

```
fields @timestamp, @message
| filter @message like /azure_service_timing/
| parse @message '"service":"*"' as service
| parse @message '"duration_seconds":*,' as duration
| stats avg(duration) as avg_seconds, max(duration) as max_seconds, count() as runs by service
| sort avg_seconds desc
```

### Total time per subscription per run

```
fields @timestamp, @message
| filter @message like /azure_subscription_timing_summary/
| parse @message '"subscription_id":"*"' as subscription_id
| parse @message '"total_duration_seconds":*,' as total
| sort @timestamp desc
| limit 50
```

### Analysis jobs cost

```
fields @timestamp, @message
| filter @message like /azure_analysis_jobs_timing/
| parse @message '"total_duration_seconds":*,' as total
| stats avg(total) as avg_analysis_seconds, max(total) as max_analysis_seconds
```

## Interpreting Results

| Finding | Likely Cause | See Fix |
|---------|-------------|---------|
| One service is >40% of total time | Azure API pagination fetching thousands of resources | [Fix B](fixes.md#fix-b-slow-individual-service) |
| All services are slow uniformly | Sequential execution — Lambda path is parallel | [Fix A](fixes.md#fix-a-enable-parallel-execution-in-eks) |
| Analysis jobs total >30s per subscription | Cypher queries running on large graph without indexes | [Fix C](fixes.md#fix-c-parallelize-analysis-jobs) |
| Neo4j write phase dominates inside a service | Single-resource transactions instead of batched UNWIND | [Fix D](fixes.md#fix-d-batch-neo4j-writes) |

## Drilling into a Single Slow Service

If e.g. `network` is consistently slow, add finer-grained timing inside `cartography/intel/azure/network.py` around the individual API fetch and Neo4j write phases:

```python
import time

t_fetch = time.time()
# ... Azure SDK list call ...
logger.info(f"[PERF] network: fetch={round(time.time()-t_fetch,2)}s items={len(results)}")

t_write = time.time()
# ... Neo4j load ...
logger.info(f"[PERF] network: neo4j_write={round(time.time()-t_write,2)}s")
```

Redeploy, run one sync, and compare `fetch` vs `neo4j_write` to pinpoint whether the bottleneck is the Azure API or the database write.
