# AGENTS.md: Cartography Intel Module Development Guide

> **For AI Coding Assistants**: This document provides comprehensive guidance for understanding and developing Cartography intel modules. It contains codebase-specific patterns, architectural decisions, and implementation details necessary for effective AI-assisted development within the Cartography project.

This guide teaches you how to write intel modules for Cartography using the modern data model approach. We'll walk through real examples from the codebase to show you the patterns and best practices.

## Table of Contents

1. [Procedure Skills](#procedure-skills) - Auto-loaded skills under `.agents/skills/`
2. [AI Assistant Quick Reference](#ai-assistant-quick-reference) - Key concepts and imports
3. [Git and Pull Request Guidelines](#git-and-pull-request-guidelines) - Commit signing and PR templates
4. [Quick Start](#quick-start-copy-an-existing-module) - Copy an existing module
5. [Quick Reference Cheat Sheet](#quick-reference-cheat-sheet) - Copy-paste templates

## Procedure Skills

Procedures for building and extending Cartography intel modules ship as Claude skills under `.agents/skills/`. Skill-aware agents auto-load each skill from its YAML frontmatter when a relevant task starts; you do not need to open the files manually. The available skills are:

- `create-module`
- `add-node-type`
- `add-relationship`
- `analysis-jobs`
- `create-rule`
- `enrich-ontology`
- `refactor-legacy`
- `troubleshooting`

## AI Assistant Quick Reference

**Key Cartography Concepts:**
- **Intel Module**: Component that fetches data from external APIs and loads into Neo4j
- **Sync Pattern**: `get()` -> `transform()` -> `load()` -> `cleanup()` -> `analysis` (optional)
- **Data Model**: Declarative schema using `CartographyNodeSchema` and `CartographyRelSchema`
- **Update Tag**: Timestamp used for cleanup jobs to remove stale data
- **Analysis Jobs**: Post-ingestion queries that enrich the graph (e.g., internet exposure, permission inheritance)

**Critical Files to Know:**
- `cartography/config.py` - Configuration object definitions
- `cartography/cli.py` - Typer-based CLI with organized help panels
- `cartography/client/core/tx.py` - Core `load()` function
- `cartography/graph/job.py` - Cleanup job utilities
- `cartography/models/core/` - Base data model classes

**Essential Imports:**
```python
import logging
from dataclasses import dataclass
from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import CartographyNodeProperties, CartographyNodeSchema, ExtraNodeLabels
from cartography.models.core.relationships import (
    CartographyRelProperties, CartographyRelSchema, LinkDirection,
    make_target_node_matcher, TargetNodeMatcher, OtherRelationships,
    make_source_node_matcher, SourceNodeMatcher,
)
from cartography.client.core.tx import load, load_matchlinks, run_write_query
from cartography.graph.job import GraphJob
from cartography.util import timeit

# For analysis jobs (optional)
from cartography.util import run_analysis_job, run_scoped_analysis_job, run_analysis_and_ensure_deps

logger = logging.getLogger(__name__)
```

**PropertyRef Quick Reference:**
```python
PropertyRef("field_name")                          # Value from data dict
PropertyRef("KWARG_NAME", set_in_kwargs=True)      # Value from load() kwargs
PropertyRef("field", extra_index=True)             # Create database index
PropertyRef("field_list", one_to_many=True)        # One-to-many relationships
```

**Debugging Tips:**
- Check existing patterns in `cartography/intel/` before creating new ones
- Ensure `__init__.py` files exist in all module directories
- Look at `tests/integration/cartography/intel/` for similar test patterns
- Review `cartography/models/` for existing relationship patterns

**Manual Write Queries:**
- Prefer `load()` / `load_matchlinks()` for normal ingestion and `GraphJob` for cleanup.
- If you must execute a handwritten write query, use `run_write_query()` instead of `neo4j_session.run()` so the write runs in a managed transaction with Cartography's retry handling.
- Reserve direct `neo4j_session.run()` for read queries or intentional low-level paths that cannot use the managed write helpers.

**Deprecation Conventions:**
- For temporary compatibility shims, legacy aliases, and migration-only edges, add a code comment in the form `# DEPRECATED: ... will be removed in v1.0.0`.
- Prefer comment-only deprecation markers for internal compatibility code that should stay quiet during normal runs.
- Use runtime warnings or log warnings only when users are actively invoking a deprecated public module or API surface.

## Git and Pull Request Guidelines

**Signing Commits**: All commits must be signed using the `-s` flag. This adds a `Signed-off-by` line to your commit message, certifying that you have the right to submit the code under the project's license.

```bash
# Sign a commit with a message
git commit -s -m "feat(module): add new feature"
```

**Pull Request Descriptions**: All pull requests must follow the template at `.github/pull_request_template.md`. Update the PR description to match the template sections if they are missing or incomplete.

## Quick Start: Copy an Existing Module

The fastest way to get started is to copy the structure from an existing module:

- **Simple module**: `cartography/intel/lastpass/` - Basic user sync with API calls
- **Complex module**: `cartography/intel/aws/ec2/instances.py` - Multiple relationships and data types
- **Reference documentation**: `docs/root/dev/writing-intel-modules.md`

For detailed step-by-step instructions, use the `create-module` skill.

---

## Quick Reference Cheat Sheet

### Standard Sync Function Template

```python
@timeit
def sync(neo4j_session: neo4j.Session, api_key: str, tenant_id: str,
         update_tag: int, common_job_parameters: dict[str, Any]) -> None:
    """
    Main sync entry point for the module.
    """
    logger.info("Starting MyResource sync")

    # 1. GET - Fetch data from API
    logger.debug("Fetching MyResource data from API")
    raw_data = get(api_key, tenant_id)

    # 2. TRANSFORM - Shape data for ingestion
    logger.debug("Transforming %d MyResource items", len(raw_data))
    transformed = transform(raw_data)

    # 3. LOAD - Ingest to Neo4j
    load_entities(neo4j_session, transformed, tenant_id, update_tag)

    # 4. CLEANUP - Remove stale data
    logger.debug("Running MyResource cleanup job")
    cleanup(neo4j_session, common_job_parameters)

    logger.info("Completed MyResource sync")
```

### Standard Load and Cleanup Patterns

```python
def load_entities(neo4j_session: neo4j.Session, data: list[dict],
                 tenant_id: str, update_tag: int) -> None:
    load(neo4j_session, YourSchema(), data,
         lastupdated=update_tag, TENANT_ID=tenant_id)

def cleanup(neo4j_session: neo4j.Session, common_job_parameters: dict[str, Any]) -> None:
    logger.debug("Running cleanup job for MyResource")
    GraphJob.from_node_schema(YourSchema(), common_job_parameters).run(neo4j_session)
```

```python
def cleanup_custom_relationships(
    neo4j_session: neo4j.Session,
    common_job_parameters: dict[str, Any],
) -> None:
    run_write_query(
        neo4j_session,
        """
        MATCH (n:YourNode)
        WHERE n.lastupdated <> $UPDATE_TAG
        DETACH DELETE n
        """,
        UPDATE_TAG=common_job_parameters["UPDATE_TAG"],
    )
```

### Required Node Properties

```python
@dataclass(frozen=True)
class YourNodeProperties(CartographyNodeProperties):
    id: PropertyRef = PropertyRef("id")                                    # REQUIRED
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)  # REQUIRED
    # Your business properties here...
```

### Relationship Direction

```python
# OUTWARD: (:Source)-[:REL]->(:Target)
direction: LinkDirection = LinkDirection.OUTWARD

# INWARD: (:Source)<-[:REL]-(:Target)
direction: LinkDirection = LinkDirection.INWARD
```

### One-to-Many Relationship Pattern

```python
# Transform: Create list field
{"entity_id": "123", "related_ids": ["a", "b", "c"]}

# Schema: Use one_to_many=True
target_node_matcher: TargetNodeMatcher = make_target_node_matcher({
    "id": PropertyRef("related_ids", one_to_many=True),
})
```

### MatchLink Pattern

```python
@dataclass(frozen=True)
class YourMatchLinkSchema(CartographyRelSchema):
    target_node_label: str = "TargetNode"
    target_node_matcher: TargetNodeMatcher = make_target_node_matcher({
        "id": PropertyRef("target_id"),
    })
    source_node_label: str = "SourceNode"
    source_node_matcher: SourceNodeMatcher = make_source_node_matcher({
        "id": PropertyRef("source_id"),
    })
    direction: LinkDirection = LinkDirection.OUTWARD
    rel_label: str = "CONNECTS_TO"
    properties: YourMatchLinkRelProperties = YourMatchLinkRelProperties()

# Required properties for MatchLinks
@dataclass(frozen=True)
class YourMatchLinkRelProperties(CartographyRelProperties):
    lastupdated: PropertyRef = PropertyRef("lastupdated", set_in_kwargs=True)
    _sub_resource_label: PropertyRef = PropertyRef("_sub_resource_label", set_in_kwargs=True)
    _sub_resource_id: PropertyRef = PropertyRef("_sub_resource_id", set_in_kwargs=True)

# Load and cleanup MatchLinks
load_matchlinks(neo4j_session, YourMatchLinkSchema(), mapping_data,
                lastupdated=update_tag, _sub_resource_label="AWSAccount", _sub_resource_id=account_id)

GraphJob.from_matchlink(YourMatchLinkSchema(), "AWSAccount", account_id, update_tag).run(neo4j_session)
```

### File Structure Template

```
cartography/intel/your_service/
├── __init__.py          # Main entry point
└── entities.py          # Domain sync modules

cartography/models/your_service/
├── entity.py            # Data model definitions
└── tenant.py            # Tenant model

tests/data/your_service/
└── entities.py          # Mock test data

tests/integration/cartography/intel/your_service/
└── test_entities.py     # Integration tests
```

### Test Utilities

```python
from tests.integration.util import check_nodes, check_rels

# Check nodes
expected_nodes = {("user-123", "alice@example.com")}
assert check_nodes(neo4j_session, "YourServiceUser", ["id", "email"]) == expected_nodes

# Check relationships
expected_rels = {("user-123", "tenant-123")}
assert check_rels(
    neo4j_session,
    "YourServiceUser", "id",
    "YourServiceTenant", "id",
    "RESOURCE",
    rel_direction_right=True,
) == expected_rels
```

### Integration Test Boundary

- Integration tests may seed prerequisite graph state with Cypher, but should exercise real Cartography `sync()` / `sync_*()` flows end-to-end whenever practical.
- Prefer mocking only external boundaries such as API clients, service discovery, credentials, and network responses; do not mock Cartography internal sync, load, or cleanup functions in integration tests.

---

Remember: Start simple, iterate, and use existing modules as references. The Cartography community is here to help!

---

## Upstream Merge Guide

This project is a fork of [lyft/cartography](https://github.com/lyft/cartography). Periodically, upstream changes must be merged into this Cloudanix fork. This section documents the strategy, commands, and validation steps.

### Repository remotes

```
origin   → git@github.com:Cloudanix/cartography.git  (our fork)
upstream → git@github.com:lyft/cartography.git       (base)
```

### Divergence overview

| Metric | Typical scale |
|--------|--------------|
| Upstream commits ahead | 1000–1500 |
| Our Cloudanix commits | 300–400 |
| Conflicts on raw merge | 200+ |

A direct `git merge upstream/master` produces 200+ conflicts. Use the **phased manual approach** below instead.

### Phased merge strategy

Do NOT run `git merge upstream/master` and resolve 200+ conflicts at once. Instead, apply upstream changes file-by-file per phase, test after each, and commit incrementally.

```
Phase 0  Setup            — ensure clean branch, establish test baseline
Phase 1  JSON files       — keep our cleanup/analysis JSON jobs (upstream deleted them)
Phase 2  Boilerplate      — README, Makefile, Dockerfile, .gitignore (take upstream)
Phase 3  config.py        — take upstream as base, inject Cloudanix fields
Phase 4  Graph layer      — querybuilder, tx.py, models/core, sync.py, helpers
Phase 5  AWS intel        — take upstream for all ~60 files, re-patch excluded_regions
Phase 6  GCP/Azure intel  — take upstream for both-modified, keep Cloudanix-only files
Phase 7  New upstream     — accept all upstream-only new integrations, models, rules
Phase 8  Final validation — full unit test suite, fix any regressions
```

**Golden rule per phase**: take upstream as base → re-apply Cloudanix patches → run tests → commit.

### Identifying conflicts before merging

```bash
# Fetch latest upstream
git fetch upstream

# Count commits each side is ahead
git rev-list origin/master..upstream/master --count   # upstream ahead
git rev-list upstream/master..origin/master --count   # our commits

# Preview conflicts without starting the merge
git merge --no-commit --no-ff upstream/master 2>&1 | grep CONFLICT | wc -l
git merge --abort   # always clean up after preview
```

### Applying upstream files safely

```bash
MERGE_BASE=$(git merge-base HEAD upstream/master)

# Take upstream version of a file
git show upstream/master:cartography/intel/aws/ec2/instances.py > cartography/intel/aws/ec2/instances.py

# See what we changed vs the merge base (to find Cloudanix patches)
git diff $MERGE_BASE HEAD -- cartography/intel/aws/__init__.py

# Find files only we have (not in upstream)
git diff upstream/master HEAD --name-only --diff-filter=A

# Find files upstream deleted that we still need
git diff upstream/master HEAD --name-only --diff-filter=D
```

### Cloudanix-specific features to preserve on every merge

These exist in our fork but not upstream. Re-apply after taking any upstream file:

| Feature | Location | What it does |
|---------|----------|-------------|
| `aws_excluded_regions` | `cartography/intel/aws/__init__.py` | Filter AWS regions from sync |
| `AWS_INTERNAL_ACCOUNTS` | `cartography/intel/aws/__init__.py` | Internal account tracking |
| `azure_requested_syncs` | `cartography/config.py` | Azure module selection |
| Azure OAuth scopes | `cartography/config.py` | `azure_redirect_uri`, `azure_graph_scope`, etc. |
| `cloudconsolelink` | 88+ intel files | Console URLs on nodes |
| `build_*_sync()` builders | `cartography/sync.py` | Per-provider sync entry points |
| `concurrent_execution()` | `cartography/intel/aws/__init__.py` | Parallel service processing |
| Cloudanix-only GCP services | `cartography/intel/gcp/` | apigateway, bigquery, cloudkms, etc. |
| Cloudanix-only Azure services | `cartography/intel/azure/` | containerregistry, iam, vmss, etc. |
| `cartography/graph/session.py` | graph layer | Cloudanix session abstraction |
| `cartography/graph/model.py` | graph layer | Cloudanix graph model |

### cloudconsolelink pattern

`cloudconsolelink` is a Cloudanix-internal package. All imports must be wrapped:

```python
# Top of each intel file:
try:
    from cloudconsolelink.clouds.aws import AWSLinker
except ImportError:
    AWSLinker = None

# Module-level instantiation:
aws_console_link = AWSLinker() if AWSLinker else None
```

Upstream files do not have these imports. After taking an upstream file, add them back if that module uses console links. The batch-fix script from the last merge is in git history.

### Handling duplicate module names

If upstream added a `service/` package and we have a `service.py` monolith (or vice versa), Python will error. Fix: delete the monolith and use the package (or merge content).

Example from last merge: `bedrock.py` (ours) vs `bedrock/` (upstream) → deleted `bedrock.py`.

### Running tests locally

```bash
# Unit tests only (no Neo4j required) — fast, run after every phase
uv run --frozen pytest tests/unit -q

# Single file
uv run --frozen pytest tests/unit/cartography/graph/test_querybuilder_simple.py -v

# Full unit + integration (needs Neo4j)
docker run -d --name neo4j --env NEO4J_AUTH=none \
  -p 7474:7474 -p 7687:7687 neo4j:5
make test_integration

# Everything (lint + unit + integration)
make test
```

### Linting and formatting

Pre-commit runs: `black`, `isort`, `flake8`, `mypy`, `pyupgrade`, plus yaml/merge checks.

```bash
# Install hooks once
uv run --frozen pre-commit install

# Run all linters (same as CI)
make test_lint
# or:
uv run --frozen pre-commit run --all-files --show-diff-on-failure

# Run individually
uv run --frozen black cartography/
uv run --frozen isort cartography/
uv run --frozen flake8 cartography/
uv run --frozen mypy cartography/
```

### Neo4j data validation after merge

Run these queries to confirm data integrity after deploying a merged build.

**1. Baseline snapshot (run before deploying)**

```cypher
// Node counts per label
MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count
ORDER BY count DESC;

// Relationship counts per type
MATCH ()-[r]->() RETURN type(r) AS rel, count(r) AS count ORDER BY count DESC;
```

Save output. After deploy, re-run and diff. Node counts should be within ~5%.

**2. Sync freshness check**

```cypher
// Nodes not updated in last sync — indicates missed data
MATCH (n:EC2Instance)
WHERE n.lastupdated < (timestamp()/1000 - 3600)   -- older than 1 hour
RETURN count(n) AS stale_ec2;

// Any nodes with null id (broken write)
MATCH (n:EC2Instance) WHERE n.id IS NULL RETURN count(n);
MATCH (n:AWSAccount)  WHERE n.id IS NULL RETURN count(n);
MATCH (n:GCPProject)  WHERE n.id IS NULL RETURN count(n);
```

**3. Relationship integrity**

```cypher
// Critical paths still intact
MATCH (a:AWSAccount)-[:RESOURCE]->(e:EC2Instance)
RETURN count(e) AS ec2_via_account;

MATCH (p:GCPProject)-[:RESOURCE]->(i:GCPInstance)
RETURN count(i) AS gcp_instances_via_project;

// Orphaned nodes (no relationships — usually a bug)
MATCH (n:EC2Instance) WHERE NOT (n)--()
RETURN count(n) AS orphaned_ec2;
```

**4. Property schema regression (run against old + new instances)**

```python
# compare_schemas.py
from neo4j import GraphDatabase

def get_schema(uri):
    driver = GraphDatabase.driver(uri, auth=None)
    with driver.session() as s:
        result = s.run("""
            MATCH (n)
            WITH labels(n)[0] AS label, keys(n) AS props
            UNWIND props AS prop
            RETURN label, collect(DISTINCT prop) AS properties
            ORDER BY label
        """)
        return {r["label"]: set(r["properties"]) for r in result}

old = get_schema("bolt://staging-old:7687")
new = get_schema("bolt://staging-new:7687")

for label in set(old) | set(new):
    removed = old.get(label, set()) - new.get(label, set())
    added   = new.get(label, set()) - old.get(label, set())
    if removed or added:
        print(f"\n{label}:")
        if removed: print(f"  REMOVED props: {removed}")
        if added:   print(f"  ADDED props:   {added}")
```

**5. High-risk areas per last merge**

| Node type | What changed | Validation query |
|-----------|-------------|-----------------|
| `EC2Instance` | NodeSchema rewrite, dropped UserData | `MATCH (n:EC2Instance) RETURN count(n), n.instanceid LIMIT 5` |
| `GCPInstance` | IAM permission edges added | `MATCH ()-[:HAS_PERMISSION]->() RETURN count(*)` |
| `AWSRoleAssignment` | `scope` field indexed | `CALL db.indexes() YIELD labelsOrTypes, properties WHERE 'AzureRoleAssignment' IN labelsOrTypes RETURN *` |
| All | `_module_name`, `_module_version` added | `MATCH (n:EC2Instance) RETURN n._module_name LIMIT 1` |

**6. Console links (Cloudanix-specific)**

If `cloudconsolelink` is installed in the environment:

```cypher
MATCH (n:EC2Instance) WHERE n.consolelink IS NOT NULL
RETURN count(n) AS ec2_with_console_links;
```

If count is 0 but should be non-zero, check that `cloudconsolelink` package is installed and `AWSLinker` is not None at runtime.
