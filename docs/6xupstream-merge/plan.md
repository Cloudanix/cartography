# Upstream Sync Plan — August 2026

Successor to `docs/5xupstream-merge/plan.md` (Neo4j 5 upgrade + May 2026 sync, completed at
`6e0afe376`). This round is a pure two-sided catch-up merge: no framework migration in flight.

## Current State (measured 2026-08-11)

| Ref | Position | Notes |
|---|---|---|
| `upstream/master` | `8ba374154` (2026-08-10) | **243 new commits** since our last sync point |
| `origin/main` | `b4f281855` (2026-08-10) | **334 new commits** (296 non-merge) since last sync |
| `upstream-merge` | `6e0afe376` (2026-05-15) | last sync of both sides; merge-base for both |
| `origin/master` | `4012511dc` (2022-01-20) | stale; 1591 behind upstream, 315 own commits — **all 315 already contained in `origin/main`** |

- Upstream remote URL is still `lyft/cartography` (works via GitHub redirect; canonical is
  `cartography-cncf/cartography`).
- Conflict surface (via `git merge-tree --write-tree`):
  - `upstream-merge` ← `origin/main`: **148 conflicted files** (124 content, 19 modify/delete, 5 add/add)
  - `upstream-merge` ← `upstream/master`: **32 conflicted files** (will grow somewhat after the main merge lands)
  - direct `origin/main` ← `upstream/master`: **326 conflicted files** — this is why we keep the
    staged `upstream-merge` branch instead of merging upstream straight into main.

### What changed on each side since May 15

**origin/main (custom work to protect — must survive the merge):**
- "Uniform neo4j" perf refactor across nearly all intel modules (`load_graph_data` /
  `run_write_query` everywhere: aws ec2 subtree, rds, iam, ssm, cloudtrail, ecs, lambda,
  elasticache, sqs, kms, elasticsearch, secretsmanager, securityhub, ecr, eks, organizations,
  azure, oci, gcp, github, bitbucket, azuredevops).
- JSON timing logging migration (all providers, structured JSON + analysis script).
- Azure IAM: Microsoft Graph token-expiry detection and fail-fast on group-member fan-out.
- API-side filtering perf work (launch template versions, Secrets Manager planned deletions,
  Dataflow/Dataproc filters, OCI lifecycle-state filters, reserved-instance tag skip).
- `DEFAULT_LOAD_BATCH_SIZE` 10000 → 500.
- GitHub repo sync from App installation instead of organization.
- Assorted fixes (subnetid keys in redshift/elasticsearch, auto_scaling_groups list handling,
  bigquery missing-role handling, parse_statement_node dict results).

**upstream/master (243 commits, 2335 files, +180k/−44k):**
- `refactor(analysis): add typed analysis jobs (#2922)` — deleted most JSON analysis jobs in
  favor of typed Python under `cartography/analysis/` (JSON GraphJob runner still exists and
  the `data/jobs/analysis/` dir still holds migration jobs).
- Dropped Python 3.10 (`requires-python = ">=3.11"`).
- New intel modules: Netlify, Modal, Microsoft O365, Cloudflare R2/Workers/WAF.
- AWS Inspector: fixAvailable/exploitAvailable/EPSS; ECR image layers; supply-chain work.
- Schema docs now generated from the data model (#3021); large `cartography/models` churn
  (945 files) and matching test churn.
- Dependency bumps (uv-managed), GitHub fork/parent attributes, rules fixes.

### Earlier-decided invariants that still hold

- Neo4j **database 5.x**, Python **driver ≥6**; composition-based `graph/session.py`
  (`execute_write`/`execute_read`, no `neo4j.Session` inheritance) — do not let a merge
  resurrect `write_transaction`.
- Keep our `client/core/tx.py` retry logic and `graph/querybuilder.py` ontology extensions
  unless upstream's version now supersedes them (re-diff during Phase 2).

---

## Strategy

Keep the proven pattern: long-lived `upstream-merge` worktree absorbs both sides, then one PR
into `main`. Merge **main first, upstream second**:

1. Conflicts with `main` are our-code-vs-our-code — easier, and custom always wins.
2. The upstream merge then happens against a tree already carrying current custom code, so
   each upstream conflict is resolved exactly once.
3. Staged totals (~148 + ~50–180) beat the direct 326, because the May sync already absorbed
   most of upstream's earlier churn.

Enable `git config rerere.enabled true` in the worktree before starting — both merges touch
overlapping files and rerere replays resolutions if a merge is aborted/redone.

---

## Phases

### Phase 0 — Prep

- [x] `git remote set-url upstream git@github.com:cartography-cncf/cartography.git` (both push/fetch); `git fetch --all --prune`.
- [x] `git config rerere.enabled true` in this worktree.
- [x] Rebuild venv: `uv sync --group dev --python 3.12` (Python 3.12.13; upstream requires ≥3.11).
- [x] Baseline: **2057 passed**, `pytest tests/unit -q` on `upstream-merge` tip (2026-08-11).
- [x] Tag safety point: `pre-sync-2026-08` at `upstream-merge` tip.

### Phase 1 — Merge `origin/main` into `upstream-merge` (148 conflicts) — DONE (`a17c286ab`)

```bash
git merge origin/main
```

Resolution rules by file class:

| File class | Rule |
|---|---|
| `cartography/intel/**` content conflicts | Take main's uniform-neo4j/custom logic as the base; re-apply any upstream-side delta that upstream-merge carried (usually mechanical — check `git log upstream-merge -- <file>` for the May upstream changes) |
| `cartography/data/jobs/cleanup/*.json` | Take main (timing/cleanup fixes) unless upstream-merge version has a Neo4j-5 Cypher fix main lacks |
| `graph/session.py`, `graph/job.py`, `graph/querybuilder.py`, `client/core/tx.py` | Diff by hand; keep composition Session + ontology querybuilder + retry tx |
| modify/delete (19) | Almost all files main deleted or renamed during perf work — follow main |
| `pyproject.toml`, `setup.py`, requirements | Union: main's pins + upstream-merge's additions |

Gate: `pytest tests/unit -q` ≥ Phase-0 baseline; pre-commit clean. Commit the merge.

### Phase 2 — Merge `upstream/master` into `upstream-merge` — DONE (`f7046ffd9`)

Single merge is preferred (243 commits but bounded conflict list). If the conflict set proves
unmanageable, fall back to chunked merges at upstream monthly boundaries (`git log --since` to
pick ~4 intermediate merge points) — rerere carries resolutions across chunks.

```bash
git merge upstream/master
```

Known decision points:

1. **Typed analysis jobs (#2922)** — upstream deleted 6 JSON analysis jobs we had customized
   (`aws_eks_asset_exposure`, `aws_foreign_accounts`, `aws_lambda_ecr`,
   `gcp_gke_asset_exposure`, `gcp_gke_basic_auth`, `gsuite_human_link`). For each: if
   upstream's typed replacement under `cartography/analysis/` covers our customization, adopt
   typed and drop the JSON; else keep our JSON (runner still supported) and verify the job is
   still wired into the sync path, with no double-run against a typed twin.
2. **Python ≥3.11** — accept; update our CI/deploy images and any 3.10-isms.
3. **`cartography/intel/aws/inspector.py`, `ecr_image_layers.py`, `cloudformation.py`,
   `intel/aws/__init__.py`** — content conflicts between our perf work and upstream feature
   work; merge both (ours for neo4j interaction style, theirs for new fields/features).
4. **Generated schema docs (#3021)** — take upstream wholesale for `docs/root/modules/**`;
   regenerate rather than hand-merge.
5. **`cartography/models/**` (945 files upstream-side)** — take upstream unless the file is
   cloudanix-custom; our custom models live mostly in modules upstream doesn't have.
6. **uv.lock / dependency bumps** — take upstream, then re-add cloudanix-only deps.

Gate: unit tests ≥ baseline + new upstream tests passing; pre-commit clean. Commit the merge.

### Phase 3 — Validation

1. `pytest tests/unit -q` — record final count.
2. Integration: `docker run -d --name neo4j5-test -p 7687:7687 -e NEO4J_AUTH=none neo4j:5-community`
   then `NEO4J_URL=bolt://localhost:7687 pytest tests/integration -q`.
3. Grep gates:
   - `grep -rn 'write_transaction\|read_transaction' cartography/ --include='*.py'` → must be empty.
   - Custom-enhancement spot checks: timing-JSON emit path, `DEFAULT_LOAD_BATCH_SIZE = 500`,
     Graph token-expiry handling in `intel/azure/iam.py`, App-installation GitHub sync.
4. Staging smoke: full sync against staging Neo4j 5, compare node/edge counts vs pre-sync
   baseline (±5% plus explained deltas from new upstream modules: Netlify, Modal, O365,
   Cloudflare R2/Workers/WAF — these only appear if configured, so expect ~0 nodes).

### Phase 4 — PR `upstream-merge` → `main`

- Push `upstream-merge`, open PR against `main`.
- PR body: link this plan, list the two merge commits, conflict counts, test results, and the
  decision log from Phase 2 (especially analysis-job dispositions).
- Review strategy for a huge PR: reviewers focus on the conflicted-file list (Phases 1–2
  tables) rather than the full diff; everything else is verbatim upstream or verbatim main.
- Merge with a **merge commit** (never squash — squashing destroys the shared history that
  keeps the next sync's conflict surface small).

### Phase 5 — Sync `origin/master` + future cadence

- After the PR merges: `git push origin upstream/master:master --force-with-lease`.
  Safe: all 315 unique `origin/master` commits are already contained in `origin/main`
  (verified: `git rev-list --count origin/main..origin/master` = 0). From then on `master` is
  a pure upstream mirror and future syncs are fast-forward pushes.
- Cadence: repeat Phases 1–4 **monthly** (or per upstream release). May→Aug drift produced
  ~180 conflicts; monthly keeps it to a few dozen.
- Keep the `pre-sync-*` tag convention for rollback points.

---

## Execution log (2026-08-11)

- **Phase 1 done** — merge commit `a17c286ab`. 148 conflicts + major silent-loss repair:
  the May sync had emptied bitbucket/azuredevops/gitlab modules, dropped cli.py `run_*`
  queue entrypoints, sync.py `build_*_sync` functions, 20 Config fields, util.py helpers,
  `intel/aws/bedrock.py`, crxcavator, gsuite/api.py, ~80 referenced cleanup/analysis
  JSONs, 23 test-data files, and 9 dependencies. All restored. Real bug fixed:
  gcp `_zones_to_regions` name-chopping. Unit gate: 2134 passed.
- **Phase 2 done** — merge commit `f7046ffd9`. 91 conflicts. Fork stance codified:
  Cloudanix legacy architecture kept for aws/azure/gcp/github orchestrators; upstream
  taken for models/**, new modules (Netlify, Modal, O365, Cloudflare, Wiz…), typed
  analysis jobs, generated schema docs. Fixed `gcp/util` package-shadowing bug,
  azure-mgmt-resource 26 import moves, uv.lock regenerated (cloudconsolelink<4.1 pin).
  Unit gate: **4523 passed, 1 xfailed, 0 failures**.
- **Phase 3 partial** — unit suite green; write_transaction grep = 0; all custom
  enhancement checklist gates verified by grep (batch-500, write_timer, azure token
  expiry, App-installation sync, API filters, run_* entrypoints, queue response dict,
  composition Session). **Integration tests + staging smoke pending — need Docker
  (neo4j:5-community) which the sandboxed session cannot start.**

### Deferred upstream features (adopt deliberately later)
- SSM public parameters sync (needs config wiring)
- AWS Inspector active sync (production runs deliberate no-op; EPSS helpers in-tree)
- Dormant azure/gcp/github data-model module suites (app_service, firewall, rbac,
  crm/cloudrun/vertex packages' tests, workload identity)

### Follow-ups
- Regenerate schema docs for adopted modules; flesh out manual schema stubs for
  azuredevops/bitbucket/crxcavator.
- Pre-existing on main, marked xfail: github repos raw-REST-shape transform test.

## Custom enhancements protection checklist

Must all be present and functional after Phase 3 (grep/test evidence, not assumption):

- [ ] Uniform neo4j interactions (`load_graph_data` / `run_write_query`) across intel modules
- [ ] JSON timing logging (all providers) + `scripts/` analysis tooling
- [ ] `DEFAULT_LOAD_BATCH_SIZE = 500`
- [ ] Azure IAM Graph token-expiry fail-fast
- [ ] API-side filtering (launch templates, secretsmanager, dataflow/dataproc, OCI lifecycle)
- [ ] GitHub App-installation repo sync
- [ ] Composition-based `graph/session.py` (`execute_write`/`execute_read`)
- [ ] `client/core/tx.py` retry logic; `querybuilder.py` ontology extensions
- [ ] Cloudanix-only intel modules (gitlab, bitbucket, azuredevops, gcp workspace, …)
- [ ] Custom analysis/cleanup JSON jobs (or their adopted typed equivalents)

## Rollback

Any phase: `git reset --hard pre-sync-2026-08` (worktree is isolated; main and master untouched
until Phases 4–5). Phase 5 force-push is the only history rewrite, and only on the already-stale
`master`.
