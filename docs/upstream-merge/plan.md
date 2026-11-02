# Cloudanix Cartography — Fork Hygiene & Upstream Merge Plan

## Context

This repo is **Cloudanix's fork** of cartography:

- `origin` → `git@github.com:Cloudanix/cartography.git` (our fork — push freely here)
- `upstream` → `git@github.com:lyft/cartography.git` (read-only; we only pull from it)

Current pain: custom code and secrets are kept local and not committed, because
secrets are baked into code files (so whole files get gitignored). This conflates
three different concerns and makes the fork hard to maintain.

## Divergence audit (vs `upstream/master`, as of plan date)

| Scope | Files | Lines |
|---|---|---|
| Total | 684 | +67590 / −6931 |
| `cartography/` core | 487 | +46288 / −5335 |
| → NEW files (upstream lacks) | 364 | +25810 |
| → MODIFIED upstream files | 123 | +20478 / −3515 |
| `cloudanix/` | — | +42 |
| `worker/` | — | +188 |
| `listener/` | — | +86 |
| `utils/` | — | +918 |
| `scripts/` | — | +550 |

Biggest in-place core rewrites (deletion count = merge-conflict risk):

```
-288 +1273  cartography/intel/gcp/compute.py
-245 +534   cartography/cli.py
-238 +856   cartography/intel/aws/iam.py
-203 +216   cartography/data/indexes.cypher
-146 +533   cartography/intel/aws/__init__.py
-131 +172   cartography/intel/aws/ecs.py
-123 +367   cartography/intel/aws/ec2/instances.py
-115 +243   cartography/intel/aws/lambda_function.py
-105 +408   cartography/intel/github/repos.py
-104 +224   cartography/intel/aws/s3.py
 -53 +133   cartography/util.py
 -51 +244   cartography/sync.py
 -40 +52    cartography/config.py
```

## Verdict: full library split is NOT feasible

The fork does not sit *on top of* cartography — it **rewrites cartography's core
intel layer**. The 123 modified files (with 3515 deletions inside upstream modules)
are in-place behavior changes that cannot be expressed as an external package
importing a pinned `pip install cartography`. Those edits *are* the upstream modules.

Goal is therefore **fork hygiene**, not library-ization. That fully solves the
stated pain ("keep files local, avoid committing").

## The three layers

| Layer | What | Lives where | Committed? |
|---|---|---|---|
| **A. Core rewrites** | 123 modified upstream files (`cli.py`, `aws/iam.py`, `gcp/compute.py`, `util.py`, `sync.py`, `config.py`, `indexes.cypher`, …) | `cartography/` | Yes — fork, managed via rebase |
| **B. Additive code** | `cloudanix/`, `worker/`, `listener/`, `app.py`, `main.py`, `utils/`, 364 new intel modules | own dirs + `cartography/intel/` | Yes — push to fork freely |
| **C. Secrets/config** | `config/`, `env*.json`, secrets currently baked into `dev.py` / Dockerfiles / `scripts/` | local + secret manager | **No** — only true secrets stay local |

The "avoid committing" instinct applies only to Layer C. Layers A and B belong in
the fork; pushing to `origin` never touches lyft.

## Plan — ordered by pain relief

### Step 1 — Audit secrets in tracked-but-gitignored files
Scan `dev.py`, `scripts/`, `Dockerfile.aws.worker`, `Dockerfile.azure.worker`,
`config/`, `env*.json` for keys/tokens/creds. Classify each finding: real secret
vs code that merely sits near a secret.

### Step 2 — Externalize secrets
- Move all secrets to env vars / secret manager, read at runtime.
- Funnel through existing `cartography/config.py` (already customized, +52/−40).
- Commit `config.example.json` / `.env.example` with keys but no values.
- Real `config/`, `env*.json` stay gitignored (already are).

### Step 3 — Un-gitignore the now-clean code
Once secrets are out, remove `dev.py`, `scripts`, `Dockerfile.aws.worker`,
`Dockerfile.azure.worker`, `config` (template only) from `.gitignore` and commit.
They are code, not secrets.

### Step 4 — Document the upstream-rebase flow
**Done** → see [upstream-merge-flow.md](upstream-merge-flow.md) (cadence,
first-catch-up strategies, conflict watchlist, validation gates, secret guard).
As of 2026-06-03: **1059 commits behind**, base 2023-12-12 — full catch-up is a
project, not a routine; doc covers chunked-merge vs cherry-pick options.

```bash
git fetch upstream
git checkout -b sync-upstream main
git merge upstream/master      # or rebase; resolve conflicts
# run tests, smoke a sync
git checkout main && git merge sync-upstream
```
Cadence: e.g. monthly or per upstream release. Record in this dir.

### Step 5 (incremental) — Shrink core coupling to reduce future conflicts
`sync.py` already supports `Sync().add_stages([(name, func)])`. We do **not** need
to edit `TOP_LEVEL_MODULES` to register `cloudanix.run`.

- Build a `build_cloudanix_sync()` in `cloudanix/` that composes stages, instead of
  editing `TOP_LEVEL_MODULES` / `build_*_sync()` in `cartography/sync.py`.
- For each core edit that is purely *additive* (extra fields, extra relationships),
  evaluate moving it behind the stage registry or a post-sync hook.
- Every edit migrated out of core = one fewer permanent merge conflict.

This is the only path that *gradually* moves toward library-style separation
without a big-bang rewrite.

## Conflict-risk watchlist (rebase hot spots)

Touch these first when resolving an upstream merge; highest deletion count =
most divergence from upstream:

`cartography/intel/gcp/compute.py`, `cartography/cli.py`,
`cartography/intel/aws/iam.py`, `cartography/intel/aws/__init__.py`,
`cartography/intel/aws/ec2/instances.py`, `cartography/intel/aws/lambda_function.py`,
`cartography/intel/aws/s3.py`, `cartography/intel/github/repos.py`,
`cartography/util.py`, `cartography/sync.py`, `cartography/config.py`,
`cartography/data/indexes.cypher`.
