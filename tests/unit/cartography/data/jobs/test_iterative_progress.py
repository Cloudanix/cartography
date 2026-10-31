"""
GraphStatement._run_iterative repeats an iterative statement until a batch makes no graph change. A batch therefore has
to stop matching the nodes it just processed, or the next batch re-selects the same LIMIT_SIZE (already reset) nodes,
changes nothing, and the loop exits with every node past the first batch untouched. For example
`MATCH (x) ... WITH x LIMIT $LIMIT_SIZE REMOVE x.prop` resets only the first batch; it needs `WHERE x.prop IS NOT NULL`.
"""
import json
import re
from pathlib import Path
from typing import List
from typing import Optional

import cartography.data.jobs

JOBS_DIR = Path(cartography.data.jobs.__file__).parent
JOB_DIRS = ('analysis', 'cleanup', 'scoped_analysis')

# Offenders other open PRs fix. Drop each entry when its PR merges (the test then guards the fixed file).
KNOWN_OFFENDERS = {
    'analysis/aws_s3_asset_exposure.json',
    'analysis/aws_s3acl_analysis.json',
    'analysis/aws_apigateway_asset_exposure.json',
    'analysis/aws_lambda_function_asset_exposure.json',
    'analysis/gcp_compute_instance_analysis.json',
    'analysis/azure_sql_asset_exposure.json',
}

# The batching clause `WITH [DISTINCT] vars LIMIT $LIMIT_SIZE`; the lookbehind skips `STARTS WITH` / `ENDS WITH`.
LIMIT_RE = re.compile(
    r'(?<!STARTS )(?<!ENDS )\bWITH\s+(?:DISTINCT\s+)?(?P<vars>[\w\s,]+?)\s+LIMIT\s+\$LIMIT_SIZE\b',
    re.IGNORECASE,
)
REMOVE_RE = re.compile(r'\bREMOVE\s+(?P<items>.*?)(?:\bRETURN\b|$)', re.IGNORECASE)
DELETE_RE = re.compile(r'\bDELETE\s+\(?\s*(?P<var>\w+)', re.IGNORECASE)
# `var.prop` (property) or `var:Label` (label) items of a REMOVE clause.
REMOVED_ITEM_RE = re.compile(r'(\w+)([.:])(\w+)')


def _filters_on(pre_limit: str, var: str, kind: str, name: str) -> bool:
    # Heuristic: the batch filters on what it removes if the MATCH/WHERE part reads the property (`var.prop IS NOT
    # NULL`, `= true`, ...), pins it in an inline map `(var:Label{prop: ...})`, or matches the removed label.
    # Removing it then drops the node out of the next batch.
    if kind == ':':
        return re.search(rf'\(\s*{var}(?::\w+)*:{name}\b', pre_limit) is not None
    if re.search(rf'\b{var}\.{name}\b', pre_limit):
        return True
    return re.search(rf'\(\s*{var}(?::\w+)*\s*\{{[^}}]*\b{name}\s*:', pre_limit) is not None


def _problem(query: str) -> Optional[str]:
    query = ' '.join(query.split())
    limit = LIMIT_RE.search(query)
    if limit is None:
        # Without a LIMIT one pass handles every match, so there is no early exit to worry about.
        return None
    pre_limit = query[:limit.start()]
    limited_vars = {v.strip() for v in limit.group('vars').split(',')}

    remove = REMOVE_RE.search(query, limit.end())
    if remove is not None:
        removed = REMOVED_ITEM_RE.findall(remove.group('items'))
        if any(_filters_on(pre_limit, var, kind, name) for var, kind, name in removed):
            return None
        return 'REMOVE without filtering on what it removes: ' + ', '.join(''.join(item) for item in removed)

    delete = DELETE_RE.search(query, limit.end())
    if delete is not None and delete.group('var') not in limited_vars:
        return f'DELETE of {delete.group("var")}, which is not the batched variable ({", ".join(limited_vars)})'
    return None


def _offenders() -> List[str]:
    found = []
    for job_dir in JOB_DIRS:
        for path in sorted((JOBS_DIR / job_dir).glob('*.json')):
            for index, statement in enumerate(json.loads(path.read_text())['statements']):
                if not statement.get('iterative'):
                    continue
                problem = _problem(statement['query'])
                if problem:
                    found.append(f'{job_dir}/{path.name} statement #{index}: {problem}')
    return found


def test_problem_flags_unfiltered_reset():
    assert _problem('MATCH (x:Foo) WITH x LIMIT $LIMIT_SIZE REMOVE x.exposed_internet RETURN COUNT(*)')
    assert _problem('MATCH (x:Foo) WITH x LIMIT $LIMIT_SIZE OPTIONAL MATCH (x)-[r:R]->() DELETE r')


def test_problem_accepts_filtered_reset_and_delete():
    assert _problem(
        'MATCH (x:Foo) WHERE x.exposed_internet IS NOT NULL WITH x LIMIT $LIMIT_SIZE REMOVE x.exposed_internet',
    ) is None
    assert _problem('MATCH (x:Foo{exposed_internet: true}) WITH x LIMIT $LIMIT_SIZE REMOVE x.exposed_internet') is None
    assert _problem(
        'MATCH (x:Foo) WHERE x.lastupdated <> $UPDATE_TAG WITH x LIMIT $LIMIT_SIZE DETACH DELETE (x)',
    ) is None
    assert _problem('MATCH (x:Foo) REMOVE x.exposed_internet') is None
    assert _problem('MATCH (x:Foo) WHERE x.lastupdated <> $UPDATE_TAG WITH x LIMIT $LIMIT_SIZE REMOVE x:Foo') is None
    assert _problem(
        "MATCH (x:Foo) WHERE x.id STARTS WITH 'https://' WITH x LIMIT $LIMIT_SIZE DETACH DELETE (x)",
    ) is None
    assert _problem('MATCH (:A)-[r:R]-(:B) WITH distinct r LIMIT $LIMIT_SIZE DELETE (r)') is None


def test_iterative_statements_make_progress_every_batch():
    offenders = [o for o in _offenders() if o.split(' ')[0] not in KNOWN_OFFENDERS]
    assert offenders == []


def test_known_offenders_are_still_offenders():
    # Keeps the allow-list honest: once a listed file is fixed, its entry must go.
    still_failing = {o.split(' ')[0] for o in _offenders()}
    assert KNOWN_OFFENDERS - still_failing == set()
