# Neo4j 5.x + Upstream Merge Plan

## Context

Two parallel workstreams need to land in this branch (`upstream-merge`):

1. **Upstream sync** — 50 upstream lyft/cartography commits already merged (commit `c8a1b993b`).
2. **Neo4j 4→5 upgrade** — Cloudanix fork (`../cartography/`, branch `neo4j-5-upgrade`) upgraded the Neo4j Python driver and database from 4.x to 5.x. These changes must be ported into `upstream-merge`.

---

## Key Findings

| Area | `../cartography/` (cloudanix) | `upstream-merge` (target) | Action |
|---|---|---|---|
| neo4j Python driver | `>=5.0.0,<6.0.0` | `>=6.0.0` | Keep 6.x — works with Neo4j 5 DB |
| `graph/session.py` | Composition-only `class Session:` ✅ | Inherits `neo4j.Session` + uses deprecated `write_transaction` ❌ | Port cloudanix version |
| `client/core/tx.py` | Simpler, older | EntityNotFound + BufferError retry logic ✅ | Keep upstream-merge version |
| `graph/querybuilder.py` | Older | OntologyFieldMapping, ConditionalNodeLabel ✅ | Keep upstream-merge version |
| JSON job Cypher syntax | CALL subquery fixes for Neo4j 5 | Needs audit | Cherry-pick cloudanix fixes |
| `graph/statement.py` | Neo4j 5 API changes | Older | Port cloudanix changes |
| `docker-compose.yml` | `neo4j:5.13.0-community` | Not present | Add with `neo4j:5-community` |

### Critical Version Note

The neo4j **Python driver 6.x** is compatible with a **Neo4j 5.x database**. Upstream already requires `neo4j>=6.0.0`. No downgrade needed — keep it. The cloudanix `neo4j>=5.0.0,<6.0.0` pin was correct at the time but upstream has since moved ahead.

### Why `session.py` matters most

Upstream-merge's `session.py` does:
```python
class Session(neo4j.Session):          # inherits neo4j.Session
    def __init__(self, neo4j_driver):
        self.neo4j_session = neo4j_driver.session()  # composition too
    def write_transaction(self, ...):   # deprecated in Neo4j 5, removed in 6
        ...
```

This is broken for Neo4j 5+ because:
- Inheriting from `neo4j.Session` without calling `super().__init__()` crashes on internal attrs (`_closed`, etc.)
- `write_transaction` is deprecated (Neo4j 5) and removed (Neo4j 6)

Cloudanix fixed this with pure composition and `execute_write`/`execute_read`:
```python
class Session:                          # no inheritance
    def __init__(self, neo4j_driver):
        self.neo4j_session = neo4j_driver.session()
    def execute_write(self, ...): ...   # current API
    def execute_read(self, ...): ...    # current API
```

---

## Decisions

**Q1: What Neo4j database version will prod run? → Neo4j 5.x database, neo4j 6.x Python driver** ✅

Note: `neo4j>=6.0.0` is the **Python driver** version, not the database version. Neo4j 6.x database does not exist — latest DB is 5.x. The driver 6.x dropped Neo4j 4.x database support; it works with Neo4j 5.x databases.

Implications:
- `neo4j>=6.0.0` Python driver (already in upstream-merge) is correct — no change needed
- `write_transaction` / `read_transaction` are **removed** in driver 6.x (not just deprecated) — must use `execute_write` / `execute_read`
- `docker-compose.yml` image: `neo4j:5-community`
- Integration test container: `neo4j:5-community`
- All cloudanix 5.x Cypher syntax fixes apply here

---

## Merge Phases

### Phase 1 — Port `session.py` (highest risk)

**File:** `cartography/graph/session.py`

**Action:** Replace upstream-merge's inheritance-based Session with cloudanix's composition-based version.

Key changes:
- Remove `class Session(neo4j.Session)` → `class Session:`
- Remove `write_transaction` → add `execute_write` / `execute_read`
- Add full context manager support (`__enter__`, `__exit__`, `close`)
- Keep error handling logic (already equivalent in both versions)

**Follow-up:** Audit all callers of `write_transaction` in the codebase and update to `execute_write`.

```bash
grep -rn 'write_transaction\|read_transaction' cartography/ --include='*.py'
```

### Phase 2 — Audit JSON job Cypher syntax

**Files:** `cartography/data/jobs/**/*.json`

Neo4j 5 changed `CALL { ... }` subquery behavior. Fixes are in cloudanix commit `95c44ffa3`.

**Action:**
1. Identify cloudanix-specific JSON jobs not in upstream (analysis + cleanup jobs under `cartography/data/jobs/`)
2. Cherry-pick Cypher syntax changes from commit `95c44ffa3` for those files
3. Run each changed query manually against a Neo4j 5 instance to confirm no syntax errors

Key syntax changes in Neo4j 5:
- `CALL { ... } WITH *` → `CALL { ... }` (implicit variable scope)
- Subquery variables must be explicitly passed or declared within the subquery

### Phase 3 — Port `statement.py` changes

**File:** `cartography/graph/statement.py`

Cloudanix's `neo4j-5-upgrade` branch modified this file. Diff and port changes that are Neo4j 5 API fixes (not cloudanix-feature-specific).

### Phase 4 — Requirements and config files

| File | Change |
|---|---|
| `pyproject.toml` | Keep `neo4j>=6.0.0` (no change needed) |
| `docker-compose.yml` | Add/update to `neo4j:5.13.0-community` |
| `docs/root/install.md` | Update install notes for Neo4j 5 |
| `aws.requirements.txt` / `gcp.requirements.txt` | Sync neo4j version if pinned |

### Phase 5 — Intel module Cypher fixes

Commit `3cd7d5527` touched ~30 cloudanix-specific intel modules for Neo4j 5 Cypher syntax.

Affected modules (cloudanix-specific, not in upstream):
- `cartography/intel/aws/apigateway.py`
- `cartography/intel/aws/bedrock.py`
- `cartography/intel/aws/cloudformation.py`
- `cartography/intel/gcp/storage.py`
- `cartography/intel/gcp/workspace.py`
- `cartography/intel/gitlab/` (multiple files)

**Action:** For each, verify the Cypher queries are Neo4j 5 compatible. Port fixes from cloudanix that aren't already superseded by upstream's versions of these files.

---

## Testing Strategy

### Step 1 — Unit tests (no Neo4j, run immediately)

```bash
ALL_PROXY="" all_proxy="" .venv/bin/pytest tests/unit -q
```

Baseline: **1740 passed** (as of 2026-05-12). Must not regress after each phase.

### Step 2 — Integration tests (requires Neo4j 6)

```bash
# Start Neo4j 6
docker run -d --name neo4j6-test -p 7687:7687 -e NEO4J_AUTH=none neo4j:5-community

# Wait for startup (~15s), then run
NEO4J_URL=bolt://localhost:7687 ALL_PROXY="" all_proxy="" \
  .venv/bin/pytest tests/integration -q

# Cleanup
docker rm -f neo4j6-test
```

### Step 3 — Smoke test on staging Neo4j 6

Use the data comparison script committed at `scripts/compare_neo4j.py` (or equivalent):

```bash
# 1. Capture baseline counts from Neo4j 4.x prod snapshot
python scripts/neo4j_compare.py --uri bolt://neo4j4-prod-snapshot:7687 > before.json

# 2. Run full cartography sync against Neo4j 5 staging
cartography --neo4j-uri bolt://neo4j5-staging:7687 \
  --aws-sync-all-profiles ...

# 3. Compare
python scripts/neo4j_compare.py --uri bolt://neo4j5-staging:7687 --baseline before.json
```

Expected: node/edge counts within ±5% of baseline (delta explained by new upstream modules).

### Step 4 — Validation checklist before prod deploy

- [ ] Unit tests: 1740+ pass
- [ ] Integration tests: 0 failures against Neo4j 5 container
- [ ] No `write_transaction` deprecation warnings in app logs
- [ ] No `CALL` subquery syntax errors in Neo4j 5 logs
- [ ] Node/edge counts on staging match expected deltas vs baseline
- [ ] `session.py` context manager works (`with` block enters/exits cleanly)
- [ ] Rollback plan ready: keep Neo4j 4.x instance warm for 24h post-cutover

---

## Execution Order

```
Phase 1: Port session.py           ← highest risk, do first
         Run unit tests             ← catch regressions immediately
Phase 2: Audit + port JSON jobs    ← cloudanix-specific Cypher
Phase 3: Port statement.py         ← smaller change
Phase 4: Update requirements/docs  ← low risk
Phase 5: Intel module Cypher fixes ← spot-check, port as needed
         Run unit tests again
         Run integration tests (need Docker)
         Staging smoke test
         Prod deploy
```

---

## Files to NOT touch

These are better in `upstream-merge` than in `../cartography/` — do not overwrite:

- `cartography/client/core/tx.py` — upstream-merge has EntityNotFound + BufferError retry logic
- `cartography/graph/querybuilder.py` — upstream-merge has OntologyFieldMapping, ConditionalNodeLabel
- All new upstream intel modules (already merged in `c8a1b993b`)

---

## References

- Cloudanix Neo4j 5 upgrade branch: `../cartography/` branch `neo4j-5-upgrade`
- Key cloudanix commits:
  - `3cd7d5527` — initial Neo4j 5.x driver upgrade
  - `95c44ffa3` — Cypher syntax fixes for Neo4j 5
  - `5d4b23426` — composition-based session.py refactor
  - `c6896f8bc` — docker-compose Neo4j image bump to 5-community
- Upstream sync commit: `c8a1b993b` (this branch)
- Unit test baseline: 1740 passed, 0 failed (2026-05-12)
