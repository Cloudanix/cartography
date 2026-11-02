"""
Tenant-isolation guard (see AGENTS.md "Tenant isolation").

Every Cloudanix tenant shares one Neo4j graph, and inventory-sync publishes whatever is reachable from a
tenant's root. So a query that looks up an existing node by a key (a name, an identifier, even a globally
unique ARN or id taken from API data) without reaching it from the syncing tenant can link one tenant's data
to another tenant's node. That shipped: classic ELB source security group by name ("default") and RDS
snapshots by DBInstanceIdentifier ("database-1") put other customers' assets into a customer's inventory.

The rule this test enforces, for the syncs Cloudanix runs (aws, azure, gcp, oci, github, gitlab, bitbucket,
azuredevops, and every analysis / cleanup job):

  A MATCH that looks up a node by a property, and a MERGE keyed on a non-unique property, must sit in a query
  anchored to the tenant: a tenant root node (CloudanixWorkspace, AWSAccount, AzureSubscription, GCPProject,
  OCITenancy, GitHubOrganization, ...) keyed by a parameter the sync itself provides (SYNC_PARAMETERS).

A parameter whose value is parsed from API data (an owner id, the subscription inside a resource id) is not an
anchor, whatever its name. Every account / subscription / project / tenancy belongs to exactly one workspace,
so the syncing root is a workspace-scoped anchor; a link to another account of the same workspace anchors on
CloudanixWorkspace{id: $WORKSPACE_ID}.

Existing sites are a ratchet BASELINE: a new site, or more sites in a file than its baseline, fails. Fewer
passes; lower the entry when you fix sites.

ponytail: regex scan. "Anchored" means the query contains an anchor, which a query can satisfy without
anchoring the looked-up node itself; the integration test pattern in AGENTS.md is the real proof. Upgrade to
a Cypher parser if the heuristic misses a real case.
"""
import ast
import json
import re
from collections import Counter
from pathlib import Path
from typing import Dict
from typing import Iterator
from typing import List
from typing import Tuple

REPO = Path(__file__).resolve().parents[3]
SOURCE = REPO / 'cartography'

# The syncs Cloudanix runs; other upstream modules (okta, pagerduty, kubernetes, ...) are never invoked.
SCANNED = re.compile(
    r"^cartography/(intel/(aws|azure|gcp|oci|github|gitlab|bitbucket|azuredevops|cloudanix)/|data/jobs/)",
)
UNUSED_JOBS = re.compile(r"(okta|semgrep|pagerduty|crowdstrike|gsuite|crxcavator|kubernetes|k8s|digitalocean)")

TENANT_ROOTS = {
    'CloudanixWorkspace', 'AWSOrganization', 'AWSAccount', 'AzureTenant', 'AzureSubscription', 'GCPOrganization',
    'GCPProject', 'OCITenancy', 'GitHubOrganization', 'GitLabGroup', 'BitbucketWorkspace', 'AzureDevOpsOrganization',
}
# Parameters the sync passes in (job parameters, or a loader argument the sync fills from them). Never add a
# name whose value is read from API data.
SYNC_PARAMETERS = {
    'WORKSPACE_ID', 'workspace_id', 'WorkspaceId', 'workspaceId', 'ORGANIZATION_ID', 'organization_id',
    'OrganizationId', 'organizationId', 'org_id', 'AWS_ID', 'AWS_ACCOUNT_ID', 'aws_account_id', 'AccountId',
    'ACCOUNT_ID', 'Account', 'INSTANCE_ARN', 'AZURE_SUBSCRIPTION_ID', 'SUBSCRIPTION_ID', 'subscription_id',
    'AZURE_TENANT_ID', 'TENANT_ID', 'tenant_id', 'tenantId', 'GCP_ORGANIZATION_ID', 'GCP_PROJECT_ID', 'ProjectId',
    'project_id', 'OCI_TENANCY_ID', 'TENANCY_ID', 'GITLAB_GROUP_ID', 'GITLAB_GROUP_NODE_ID', 'GroupId',
    'WORKSPACE_UUID', 'uuid', 'OrgLogin', 'OrganizationName', 'OrgName',
}
# Shared catalog / principal nodes: one node per global fact, linked from many tenants on purpose (AGENTS.md
# rule 5). Looking one up by its key is fine; hopping from it to other tenant data is not.
SHARED_LABELS = {
    'CVE', 'ProgrammingLanguage', 'PythonLibrary', 'Dependency', 'IpRange', 'Ipv6Range', 'Ip', 'AWSTag', 'Tag',
    'AzureTag', 'GCPLabel', 'OCITag', 'ECRImage', 'GitHubUser', 'GitLabMember', 'AzureDevOpsUser', 'AWSPrincipal',
    'GCPPrincipal', 'GCPExternalPrincipal', 'AWSExternalPrincipal', 'AzureExternalPrincipal', 'OCIExternalPrincipal',
}
# MERGE keys that are unique only inside one tenant scope.
RISKY_MERGE_KEYS = {
    'name', 'db_instance_identifier', 'db_cluster_identifier', 'username', 'login', 'email', 'full_path', 'path',
    'group_name', 'keyfingerprint', 'value',
}
# (label, key) pairs whose value is globally unique, so a MERGE on them cannot cross tenants.
GLOBALLY_UNIQUE = {
    ('S3Bucket', 'name'),  # bucket names are unique across all AWS accounts
}

NODE = re.compile(r"\((\w*)\s*:\s*([\w:]+)\s*\{([^{}]*)\}")
CLAUSE = re.compile(r"\b(MATCH|MERGE|CREATE)\b", re.I)
PARAMETER_VALUE = re.compile(r"^\s*\$(\w+)\s*$")

# Known sites, to burn down. Never raise a count: anchor the query instead (AGENTS.md).
BASELINE: Dict[str, int] = json.loads((Path(__file__).parent / 'tenant_isolation_baseline.json').read_text())


def _cypher_strings() -> Iterator[Tuple[str, str]]:
    for path in sorted(SOURCE.rglob('*.py')):
        rel = str(path.relative_to(REPO))
        if not SCANNED.search(rel):
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value
            elif isinstance(node, ast.JoinedStr):
                text = ''.join(v.value if isinstance(v, ast.Constant) else '{X}' for v in node.values)
            else:
                continue
            if re.search(r"\b(MATCH|MERGE)\b", text):
                yield rel, text
    for path in sorted((SOURCE / 'data' / 'jobs').rglob('*.json')):
        rel = str(path.relative_to(REPO))
        if UNUSED_JOBS.search(path.name):
            continue
        for statement in json.loads(path.read_text()).get('statements', []):
            yield rel, statement.get('query', '')


def _clause_at(query: str, position: int) -> str:
    clause = 'MATCH'
    for match in CLAUSE.finditer(query, 0, position):
        clause = match.group(1).upper()
    return clause


def violations(query: str) -> List[str]:
    """The Label.key lookups in one query that are not anchored to the tenant ([] when anchored)."""
    found, anchored = [], False
    for node in NODE.finditer(query):
        labels = set(node.group(2).split(':'))
        clause = _clause_at(query, node.start())
        for prop in node.group(3).split(','):
            if ':' not in prop:
                continue
            key, value = (part.strip() for part in prop.split(':', 1))
            parameter = PARAMETER_VALUE.match(value)
            if labels & TENANT_ROOTS and parameter and parameter.group(1) in SYNC_PARAMETERS:
                anchored = True
                continue
            label = node.group(2).split(':')[0]
            if labels & SHARED_LABELS or (label, key) in GLOBALLY_UNIQUE:
                continue
            if clause == 'MATCH' or (clause == 'MERGE' and key in RISKY_MERGE_KEYS):
                found.append(f'{label}.{key}')
    return [] if anchored else found


def unanchored_sites() -> Counter:
    sites: Counter = Counter()
    for path, query in _cypher_strings():
        for lookup in violations(query):
            sites[f'{path}|{lookup}'] += 1
    return sites


def test_no_new_unanchored_lookups():
    grown = {site: count for site, count in unanchored_sites().items() if count > BASELINE.get(site, 0)}
    assert not grown, (
        'Cypher looks up a node by a key without anchoring the query to the tenant (AGENTS.md "Tenant '
        f'isolation"): {grown}. Reach the node from the syncing root keyed by a sync parameter, or from '
        'CloudanixWorkspace{id: $WORKSPACE_ID} for another account of the same workspace.'
    )


def test_guard_flags_the_patterns_that_leaked():
    leaked = [
        'MATCH (elb:LoadBalancer{id: item.id}), (group:EC2SecurityGroup{name: item.group_name})',
        'MATCH (rdsInstance:RDSInstance {db_instance_identifier: snapshot.DBInstanceIdentifier})',
        # a root keyed by a value parsed from API data is not an anchor
        'MATCH (rg_sub:AzureSubscription{id: $resource_group_subscription_id})-[:RESOURCE]->'
        '(rg:AzureResourceGroup{name: $resource_group})',
        # a globally unique id taken from API data still needs the tenant
        'MATCH (vpc:AWSVpc{id: $PeerVpcId}) MERGE (a)-[:PEERED]->(vpc)',
    ]
    for query in leaked:
        assert violations(query), query


def test_guard_accepts_anchored_and_shared_lookups():
    ok = [
        'MATCH (:AWSAccount{id: $AWS_ACCOUNT_ID})-[:RESOURCE]->(group:EC2SecurityGroup{name: item.group_name})',
        'MATCH (:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization)-[:OWNER]->(:AWSAccount)'
        '-[:RESOURCE]->(repo:ECRRepository{uri: $uri})',
        'MATCH (n:ProgrammingLanguage) WHERE NOT (n)--() DELETE n',
        'MERGE (pl:ProgrammingLanguage{id: lang.name})',
    ]
    for query in ok:
        assert not violations(query), query
