"""
Tenant-isolation guard (see AGENTS.md "Tenant isolation").

Every Cloudanix tenant shares one Neo4j graph. A MATCH/MERGE that keys a node on a property that is
unique only inside one account, subscription, project or VPC (a name, a DB identifier, an email ...)
and is not anchored to the syncing tenant links one tenant's data to every other tenant's same-named
node. That shipped twice: classic ELB source security group by name ("default") and RDS snapshots by
DBInstanceIdentifier ("database-1") put other customers' assets into a customer's inventory.

This test scans every Cypher string in cartography/ (Python literals and job JSON) for such a key in a
query that carries no tenant parameter. Existing sites are a ratchet BASELINE: a new site, or more sites
in a file than its baseline, fails. When you fix a site, lower its count (or drop the entry).

ponytail: regex scan. "Anchored" means the query mentions any tenant parameter at all, which a query
can satisfy without anchoring the risky node; the integration test pattern in AGENTS.md is the real proof.
Upgrade to a Cypher parser if the heuristic misses a real case.
"""
import ast
import json
import re
from collections import Counter
from pathlib import Path
from typing import Dict
from typing import Iterator
from typing import Tuple

REPO = Path(__file__).resolve().parents[3]
SOURCE = REPO / 'cartography'
JOBS = SOURCE / 'data' / 'jobs'

# Node keys that are unique only inside one tenant scope.
RISKY_NODE_KEY = re.compile(
    r"\(\w*:(\w+)\s*\{\s*(name|db_instance_identifier|db_cluster_identifier|username|login|email|"
    r"full_path|path|group_name|keyfingerprint|value)\s*:",
)
TENANT_PARAMETER = re.compile(r"\$\w*(account|workspace|subscription|project|tenancy|tenant|organization|org)\w*", re.I)

# (label, key) pairs whose value is globally unique, so matching on them cannot cross tenants.
GLOBALLY_UNIQUE = {
    ('S3Bucket', 'name'),  # bucket names are unique across all AWS accounts
    ('TestNode', 'name'),  # docstring example in client/core/tx.py
}

# Known unanchored sites, to burn down. Do not add to this: anchor the query instead (AGENTS.md).
BASELINE: Dict[str, int] = {
    "cartography/intel/aws/ec2/auto_scaling_groups.py|LaunchConfiguration.name": 1,
    "cartography/intel/aws/ec2/load_balancers.py|EC2SecurityGroup.name": 1,
    "cartography/intel/aws/rds.py|DBSubnetGroup.name": 1,
    "cartography/intel/aws/rds.py|RDSCluster.db_cluster_identifier": 1,
    "cartography/intel/aws/rds.py|RDSInstance.db_instance_identifier": 2,
    "cartography/intel/aws/route53.py|AWSDNSRecord.value": 1,
    "cartography/intel/azure/aks.py|AzureResourceGroup.name": 8,
    "cartography/intel/azure/compute.py|AzureResourceGroup.name": 7,
    "cartography/intel/azure/cosmosdb.py|AzureResourceGroup.name": 5,
    "cartography/intel/azure/function_app.py|AzureResourceGroup.name": 8,
    "cartography/intel/azure/key_vaults.py|AzureResourceGroup.name": 1,
    "cartography/intel/azure/monitor.py|AzureResourceGroup.name": 1,
    "cartography/intel/azure/network.py|AzureResourceGroup.name": 10,
    "cartography/intel/azure/securitycenter.py|AzureResourceGroup.name": 1,
    "cartography/intel/azure/sql.py|AzureResourceGroup.name": 13,
    "cartography/intel/azure/storage.py|AzureResourceGroup.name": 8,
    "cartography/intel/crxcavator/crxcavator.py|GSuiteUser.email": 2,
    "cartography/intel/gcp/apigateway.py|GCPPrincipal.email": 2,
    "cartography/intel/gcp/cloudfunction.py|GCPPrincipal.email": 1,
    "cartography/intel/gcp/cloudkms.py|GCPPrincipal.email": 1,
    "cartography/intel/gcp/compute.py|GCPPrincipal.email": 1,
    "cartography/intel/gcp/compute.py|GCPServiceAccount.email": 1,
    "cartography/intel/kubernetes/pods.py|KubernetesNamespace.name": 1,
    "cartography/intel/kubernetes/secrets.py|KubernetesNamespace.name": 1,
    "cartography/intel/kubernetes/services.py|KubernetesNamespace.name": 1,
    "cartography/intel/okta/awssaml.py|OktaApplication.name": 1,
}


def _cypher_strings() -> Iterator[Tuple[str, str]]:
    for path in sorted(SOURCE.rglob('*.py')):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.search(
                r"\b(MATCH|MERGE)\b", node.value,
            ):
                yield str(path.relative_to(REPO)), node.value
    for path in sorted(JOBS.rglob('*.json')):
        for statement in json.loads(path.read_text()).get('statements', []):
            yield str(path.relative_to(REPO)), statement.get('query', '')


def unanchored_sites() -> Counter:
    sites: Counter = Counter()
    for path, query in _cypher_strings():
        if TENANT_PARAMETER.search(query):
            continue
        for match in RISKY_NODE_KEY.finditer(query):
            label, key = match.group(1), match.group(2)
            if (label, key) not in GLOBALLY_UNIQUE:
                sites[f'{path}|{label}.{key}'] += 1
    return sites


def test_no_new_unanchored_non_unique_node_keys():
    grown = {
        site: count for site, count in unanchored_sites().items() if count > BASELINE.get(site, 0)
    }
    assert not grown, (
        'Cypher keys a node on a non-unique property without anchoring it to the tenant '
        f'(AGENTS.md "Tenant isolation"): {grown}. Anchor the node to the syncing account / '
        'subscription / project / tenancy, or key it on a globally unique id.'
    )


def test_guard_flags_the_patterns_that_leaked():
    leaked = [
        'MATCH (elb:LoadBalancer{id: item.id}), (group:EC2SecurityGroup{name: item.group_name})',
        'MATCH (rdsInstance:RDSInstance {db_instance_identifier: snapshot.DBInstanceIdentifier})',
    ]
    anchored = (
        'MATCH (:AWSAccount{id: $AWS_ACCOUNT_ID})-[:RESOURCE]->'
        '(group:EC2SecurityGroup{name: item.group_name})'
    )
    for query in leaked:
        assert RISKY_NODE_KEY.search(query) and not TENANT_PARAMETER.search(query)
    assert TENANT_PARAMETER.search(anchored)
