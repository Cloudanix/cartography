# Azure Inventory Processing — Performance Revision

This directory documents the work to measure and reduce end-to-end processing time for the Azure inventory worker deployed as an EKS job.

## Problem

The Azure worker (`Dockerfile.azure.worker`, built by `scripts/k8s/azure.build.sh`) takes too long to finish a full inventory sync for a subscription. The job runs sequentially through 12 service modules and 9 Neo4j analysis jobs with no visibility into which step consumes the most time.

## Approach

The revision has three phases:

| Phase | Document | Status | Goal |
|-------|----------|--------|------|
| 1 — Instrument | [instrumentation.md](instrumentation.md) | Done | Add structured timing logs, zero behavior change |
| 2 — Analyze | [analysis.md](analysis.md) | Ready | Query CloudWatch Logs to rank slow services |
| 3 — Fix | [fixes.md](fixes.md) | Pending data | Apply the right optimization based on the data |

## Key Files

| File | Role |
|------|------|
| `cartography/intel/azure/__init__.py` | Orchestration — timing added in `_sync_one_subscription` (line 80) and `_sync_multiple_subscriptions` (line 216) |
| `cartography/intel/azure/resources.py` | Registry of all 12 service sync functions (`RESOURCE_FUNCTIONS` dict) |
| `app.py` | EKS entrypoint (`CDX_RUN_AS=EKS` poll loop) |
| `Dockerfile.azure.worker` | Container image definition |
| `scripts/k8s/azure.build.sh` | Build + push to ECR |

## Services Timed

`iam`, `network`, `aks`, `images`, `cosmosdb`, `function_app`, `key_vaults`, `compute`, `sql`, `storage`, `monitor`, `securitycenter`

Plus 9 post-subscription analysis jobs (Cypher queries against Neo4j).
