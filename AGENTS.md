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
2. **To MATCH by anything else, anchor that node to the tenant in the same pattern.** For example:
   `(:AWSAccount{id: $AWS_ACCOUNT_ID})-[:RESOURCE]->(n:X{name: ..., region: ...})`. Narrow further to
   region or VPC when the key is only unique there. Anchor **both ends** of every link.
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

`tests/unit/cartography/test_tenant_isolation.py` runs in `make test_unit` (CI). It fails when Cypher
keys a node on a non-unique property (`name`, `db_instance_identifier`, `email`, ...) in a query that
carries no tenant parameter.

- Existing sites are listed in its `BASELINE` for burn-down. **Never raise a baseline count. Anchor
  the query instead.** When you fix a site, lower or remove its entry.
- If a property really is globally unique (S3 bucket name), add it to `GLOBALLY_UNIQUE` with the
  reason.
- The scan is a heuristic. A query that mentions a tenant parameter passes even if the risky node
  itself is not anchored. Rule 7's integration test is the real proof.

### Before merging a loader or job change

- Ask: what does this do when a second tenant has a node with the same name, id or value?
- Size it on prod: count edges whose two ends are owned by different workspaces. Look for
  multi-owner nodes, i.e. `RESOURCE` edges from accounts of different workspaces.
