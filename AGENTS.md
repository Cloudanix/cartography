# Repository guidelines (Cloudanix cartography fork)

For humans and coding agents. Read the tenant-isolation rules before writing any Cypher: loaders in
`cartography/intel/**`, and analysis, cleanup and scoped jobs in `cartography/data/jobs/**`.

## Tenant isolation (non-negotiable)

Every Cloudanix customer (workspace) shares **one** Neo4j graph. Tenant chain:
`(:CloudanixWorkspace)-[:OWNER]->(:AWSOrganization)-[:OWNER]->(:AWSAccount)-[:RESOURCE]->(resource)`.
Azure (tenant/subscription), GCP (organization/project), OCI (tenancy/compartment) and the SCM
integrations follow the same shape. inventory-sync reads a tenant's assets by walking edges out of
that tenant's root, so **an edge into another tenant's node publishes that node to the wrong
customer.** This has happened twice in production:

- A classic ELB's `SourceSecurityGroup` was matched by name (`default`), which put about 8.6k other
  customers' security groups into two workspaces.
- RDS snapshots were matched to instances by `DBInstanceIdentifier` (`database-1`), which put other
  customers' snapshots into customer inventories.

### Rules

1. **MERGE keys must be globally unique**: full ARN, OCID, Azure ARM id, GCP self-link /
   `projects/{p}/...` name, a host-qualified SCM URL, or a composite that embeds one
   (`{parent_id}/{short}`). Never key a node on a name, login, username, path, short or numeric id,
   IP, CIDR, email, digest or region alone.
2. **Every lookup of an existing node is anchored to the tenant, whatever the key.** A MATCH by name,
   identifier, or even a globally unique ARN or id read from API data reaches the node from the
   syncing root in the same pattern, keyed by a parameter the sync provides:
   `(:AWSAccount{id: $AWS_ACCOUNT_ID})-[:RESOURCE]->(n:X{name: ..., region: ...})`. Each account,
   subscription, project, tenancy and SCM org belongs to exactly one workspace, so the syncing root is
   workspace-scoped. A link to **another** account / subscription / project of the same customer
   anchors on the workspace: `(:CloudanixWorkspace{id: $WORKSPACE_ID})-[:OWNER]->(:AWSOrganization)
   -[:OWNER]->(:AWSAccount)-[:RESOURCE]->(n)`. A parameter whose value is parsed from API data (an
   `OwnerId`, the subscription inside an ARM id) is never an anchor. Narrow further to region or VPC
   when the key is only unique there. Anchor **both ends** of every link.
3. **No graph-wide MATCH / SET / MERGE / DELETE** in a sync, analysis or cleanup statement. Every job
   statement starts from `$WORKSPACE_ID` / `$AWS_ID` / the subscription, project or tenancy. A node
   pattern you leave unanchored on purpose needs a comment saying why.
4. **Never follow a foreign id.** If an API returns another account's resource (a cross-account
   replica source, a shared snapshot, a peer VPC), do not link to, set properties on, or claim
   (`RESOURCE`) that tenant's node.
5. **Shared or catalog nodes** (CVE, ProgrammingLanguage, IpRange `0.0.0.0/0`, ECR image digests,
   external principals, tags) hold only global facts. Tenant-specific values go on the edge. Never
   hop from a shared node back out to other resources without re-anchoring to the tenant.
6. **Tenant cleanup deletes its own edges, never shared nodes.** `lastupdated` on a shared node holds
   whichever tenant wrote it last. Orphan sweeps are separate global jobs.
7. **Every new link query ships an integration test** that puts the same name or key in a second
   tenant (and, where relevant, a second region or VPC) and asserts no edge reaches it. Examples:
   `tests/integration/cartography/intel/aws/ec2/test_classic_elb_source_security_group.py`,
   `tests/integration/cartography/intel/aws/test_rds_tenant_scope.py`.

### Enforcement

`tests/unit/cartography/test_tenant_isolation.py` runs in `make test_unit` (CI) over the syncs Cloudanix
runs (aws, azure, gcp, oci, github, gitlab, bitbucket, azuredevops) and every analysis / cleanup job. It
fails when a query looks up a node by a property (any MATCH, or a MERGE on a non-unique key such as
`name`) and is not anchored: no tenant root (`CloudanixWorkspace`, `AWSAccount`, `AzureSubscription`,
`GCPProject`, `OCITenancy`, `GitHubOrganization`, ...) keyed by a sync parameter (`SYNC_PARAMETERS`).

- Existing sites are in `tests/unit/cartography/tenant_isolation_baseline.json` for burn-down. **Never
  raise a count. Anchor the query instead.** Fewer sites pass; lower the entries when you fix them.
- Never add a name to `SYNC_PARAMETERS` whose value comes from API data.
- Shared catalog / principal labels (rule 5) are in `SHARED_LABELS`. A property that really is globally
  unique (S3 bucket name) goes in `GLOBALLY_UNIQUE` with the reason.
- The scan is a heuristic. A query that contains an anchor passes even if the looked-up node itself is
  not reached from it. Rule 7's integration test is the real proof.

### Before merging a loader or job change

- Ask: what does this do when a second tenant has a node with the same name, id or value?
- Size it on prod: count edges whose two ends are owned by different workspaces. Look for
  multi-owner nodes, i.e. `RESOURCE` edges from accounts of different workspaces.
