# Step 4 — Upstream Merge / Rebase Flow

How to pull `lyft/cartography` changes into the Cloudanix fork without
re-creating the "huge divergence" pain. Part of the fork-hygiene plan
([plan.md](plan.md)).

## Remotes

```
origin    git@github.com:Cloudanix/cartography.git   # our fork — push here
upstream  git@github.com:lyft/cartography.git         # read-only — pull only
```

If `upstream` is missing:

```bash
git remote add upstream git@github.com:lyft/cartography.git
git fetch upstream
```

## Current state (as of 2026-06-03)

| Metric | Value |
|---|---|
| Commits **behind** `upstream/master` | **1059** |
| Commits **ahead** (our changes) | 2364 |
| Last common base | `a5a28f978` — **2023-12-12** (~2.5 years stale) |
| Modified upstream core files | 123 (see [plan.md](plan.md) watchlist) |

**Implication:** a single catch-up merge from 2.5 years back, across 123
rewritten core files, is a *project* — not a routine. Treat the first catch-up
and the ongoing cadence as two different things (below).

## Ongoing cadence (the goal state)

Small, frequent merges so conflicts stay tiny. Once caught up, do this monthly
or per upstream release:

```bash
git fetch upstream
git switch -c sync-upstream-$(date +%Y%m%d) main

git merge upstream/master          # resolve conflicts (watchlist first)

# validate before merging back
make test_lint
make test_unit
# smoke a real sync against a scratch Neo4j (see "Smoke test")

git switch main
git merge --no-ff sync-upstream-$(date +%Y%m%d)
git push origin main
```

Rebase vs merge: use **merge** here, not rebase. `main` is shared/pushed and has
2364 commits — rebasing rewrites all of them and breaks everyone's clones. Merge
keeps history intact.

## First catch-up (the 1059-commit backlog) — do NOT do in one shot

Two viable strategies; pick per appetite:

### Option A — Chunked merge (recommended if you want upstream's 2.5yr of work)
Merge upstream in time-sliced steps so each conflict set is reviewable:

```bash
git fetch upstream
# pick intermediate upstream commits (e.g. one tag / ~quarter at a time)
git log --oneline upstream/master | tail   # find older anchors
git merge <upstream_commit_from_2024Q1>    # resolve, test
git merge <upstream_commit_from_2024Q3>    # resolve, test
...
git merge upstream/master                  # final
```

Each step: resolve → `make test_unit` → commit. Conflicts shrink because you
never face 2.5 years at once.

### Option B — Cherry-pick targeted fixes (recommended if core has diverged too far)
Don't chase the whole backlog. Pull only specific upstream commits you need
(a bug fix, a new intel module, a CVE patch):

```bash
git fetch upstream
git log --oneline upstream/master -- cartography/intel/aws/iam.py   # find the fix
git cherry-pick <sha>                                               # resolve, test
```

Given 123 rewritten core files, Option B is often the pragmatic choice — our
core has drifted so far that wholesale upstream merges may fight every file.

## Conflict watchlist (resolve these first)

Highest divergence from upstream → most conflict-prone. Full numbers in
[plan.md](plan.md):

```
cartography/intel/gcp/compute.py        cartography/cli.py
cartography/intel/aws/iam.py            cartography/intel/aws/__init__.py
cartography/intel/aws/ec2/instances.py  cartography/intel/aws/lambda_function.py
cartography/intel/aws/s3.py             cartography/intel/github/repos.py
cartography/util.py                     cartography/sync.py
cartography/config.py                   cartography/data/indexes.cypher
```

`cartography/sync.py` conflicts shrink permanently once Step 5
(`build_cloudanix_sync()`) lands — see [plan.md](plan.md).

## Validation gates (run before merging `sync-upstream` back to `main`)

From [Makefile](../../Makefile):

```bash
make test_lint          # pre-commit: flake8, autopep8, pyupgrade, import order
make test_unit          # pytest tests/unit  (no DB needed)
make test_integration   # pytest tests/integration  (needs Neo4j)
```

Lint config: `setup.cfg` (flake8 max-line 120; mypy strict on
`cartography.intel.*`). Hooks: `.pre-commit-config.yaml`.

### Smoke test (catch runtime breakage units miss)

After tests pass, run one real sync against a scratch Neo4j and confirm the
`cloudanix-workspace` + cloud stages complete:

```bash
docker compose up -d neo4j        # or point at a throwaway instance
# run the relevant entrypoint (dev.py / app.py) against a dev workspace
python dev.py <gcp|aws|azure> <args>   # uses scripts/*.env.dev.yml
```

## Secret safety during merges

Upstream never carries our secrets, but a merge can resurrect a deleted line or
re-add a file. Before pushing a sync branch, re-run the audit guard from
[step1-secret-audit.md](step1-secret-audit.md):

```bash
git diff --cached | grep -iE 'gloas-|Piwbiv|fejboz|wHi8Q~|ypU8Q~|jFWcmGKL|774118602354|Cloudanix@123'
```

Empty output = safe to push.

## Record each sync

Append a line here after every successful catch-up so the next person knows the
last base:

| Date | Merged up to (upstream sha) | Strategy | Notes |
|---|---|---|---|
| 2023-12-12 | `a5a28f978` | initial fork base | — |
