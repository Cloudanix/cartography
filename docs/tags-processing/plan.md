# Tags Collection — Gap Analysis & Expansion Plan

Companion to [design.md](./design.md). Goal: app & data classification in the Cloudanix
console is driven entirely by tags in `d_asset_tags`, which are driven entirely by what
cartography writes into the graph. This document inventories exactly which resources
carry tags today, which don't, which are wired but silently broken, and lays out a
prioritized plan to close the gaps.

Counts below are measured against the current tree (branch `tags-coverage-expansion`),
not the pre-expansion baseline. Re-measure before publishing a customer-facing coverage
report; §2.1/§3.1/§5.1 are generated from the source, so they drift the moment a mapping
or a `sync_labels`/`sync_tags` call site is added.

## 1. Coverage summary

| Provider | Mechanism | Node labels synced | Tags captured | Wired but broken | Not covered |
|---|---|---|---|---|---|
| AWS | Hardcoded allow-list → `AWSTag` nodes | 122 | 77 (79 API filters) | 0 | ~45 |
| GCP | Opt-in `label.sync_labels()` → `GCPLabel` nodes | 86 | 38 (+2 as property) | 0 | ~46 |
| Azure | Generic ARM crawl → `AzureTag` nodes | 94 | ~25 (structural) | 0 | ~69 (mostly child resources) |
| OCI | Shared `OCITag` helper + per-resource wiring | 44 | 28 | 0 | ~16 |

Two coverage filters stack: a resource's tags reach the console only if (a) cartography
writes them to the graph AND (b) the node label is listed in inventory-sync's
`config/inventory.<provider>.json`. Tags for labels absent from that config are written
but never read. This was true of `AWSLambdaLayer`, `ECSContainerInstance`,
`AWSLambdaEventSourceMapping` and `AWSTransitGatewayAttachment` at the time of the
original audit, and the 33 AWS labels added since have **not** been checked against the
deployed inventory config — that audit is a release gate (§8), not an assumption.

---

## 2. AWS

Source of truth: `TAG_RESOURCE_TYPE_MAPPINGS` in
`cartography/intel/aws/resourcegroupstaggingapi.py` — 79 Resource Groups Tagging API
filters → 77 node labels (two labels are reached by more than one filter). No AWS module
stores tags as node properties (EC2/VPC read `Tags` only to derive `eks:cluster-name` /
`Name` and discard the rest).

Two mechanisms exist beyond a plain mapping row:

- `path` — an explicit graph path for sub-resources that do not hang directly off the
  account (`ECSTask`, `ECSContainerInstance`, `ECSService`, `ELBV2Listener`,
  `EKSClusterNodeGroup`). Without it the default `(:AWSAccount)-[:RESOURCE]->` MATCH
  never fires and the tags are fetched from AWS and silently dropped.
- `GLOBAL_RESOURCE_TYPES` — types the tagging API only reports in us-east-1
  (`cloudfront:distribution`, `route53:hostedzone`) plus `iam:role`, whose tags come
  from the region-independent `get_role_tags()`. These sync once per account instead of
  once per region.

### 2.1 Working today (77 labels)

APIGatewayClientCertificate, APIGatewayResource, APIGatewayRestAPI, AWSBedrockAgent,
AWSBedrockCustomModel, AWSBedrockCustomisationJob, AWSBedrockGuardRail,
AWSCloudTrailTrail, AWSCloudWatchAlarm, AWSCloudWatchLogGroup, AWSCloudformationStack,
AWSCloudfrontDistribution, AWSConfigRule, AWSDNSZone, AWSEventBridgeEventBus,
AWSEventBridgeRule, AWSGroup, AWSInternetGateway, AWSLambda,
AWSLambdaEventSourceMapping, AWSLambdaLayer, AWSPolicy, AWSRole (special-cased via
`iam.get_role_tags` — the Tagging API lacks `iam:role`), AWSSESIdentity, AWSSNSTopic,
AWSSagemakerCluster, AWSSagemakerDomain, AWSSagemakerEndpoint, AWSSagemakerModel,
AWSSagemakerNotebookInstance, AWSSagemakerTrainingJob, AWSTransitGateway,
AWSTransitGatewayAttachment, AWSUser, AWSVpc, AWSWAFClassicWebACL, AWSWAFv2WebACL,
AutoScalingGroup, DBSubnetGroup, DynamoDBTable, EBSSnapshot, EBSVolume, EC2Image,
EC2Instance, EC2KeyPair, EC2ReservedInstance, EC2RouteTable, EC2SecurityGroup,
EC2Subnet, ECRRepository, ECSCluster, ECSContainerInstance, ECSService, ECSTask,
ECSTaskDefinition, EKSCluster, EKSClusterNodeGroup, ELBV2Listener, EMRCluster, ESDomain,
ElasticIPAddress, ElasticacheCluster, KMSKey, KinesisStream, LaunchTemplate,
LoadBalancer, LoadBalancerV2, NetworkInterface, RDSCluster, RDSInstance,
RDSReservedDBInstance, RDSSnapshot, RedshiftCluster, S3Bucket, SQSQueue,
SecretsManagerSecret, SecurityHub.

### 2.2 Previously wired but broken (now fixed)

The load query used to require a **direct** `(:AWSAccount)-[:RESOURCE]->(resource)` edge:

| Label | Why it never matched | Resolution |
|---|---|---|
| `ECSTask`, `ECSContainerInstance` | Hang off `ECSCluster` (`HAS_TASK`, `HAS_CONTAINER_INSTANCE`) | `path` override |
| `ELBV2Listener` | Hangs off its load balancer (`ELBV2_LISTENER`); the mapping also keyed on a `name` property listener nodes never get | `path` override + key on `id` (the full ARN) |
| `ECSContainer`, `ELBListener` (classic) | Not taggable resource types at all — the filters only ever burned API calls | mappings removed |

Regression coverage lives in `tests/unit/cartography/intel/aws/test_resourcegroupstaggingapi.py`
(`test_mappings_reachable_from_account`, `test_load_query_uses_mapping_path`,
`test_untaggable_types_removed`).

### 2.3 Not covered (~45 labels) — remaining targets

Most of the original 76-label gap is closed. What is left splits three ways:

**Taggable, needs a fetcher other than RGTA:**

| Target | Why |
|---|---|
| `AWSPermissionSet` (IAM Identity Center) | Needs the SSO Admin `ListTagsForResource` API, not RGTA — a small per-account fetcher like `get_role_tags` |
| SSM managed instances | Tags come from `ssm:DescribeInstanceInformation` / managed-instance tags; the SSM module does not create a taggable node with a matching id today |

**Taggable in principle, blocked on a node-shape mismatch:**

| Target | Blocker |
|---|---|
| `ECRRepositoryImage` / `ECRImage` | Image tags are ECR image tags (a different concept from resource tags); the repository already carries resource tags |
| `AWSCloudWatchMetric` | Metrics are not resources and carry no tags |

**Not taggable — permanently out of scope** (do not re-litigate these): policy
statements, ACLs, IP ranges/rules, route/route-table associations, private IPs, CIDR
blocks, peering connections, name servers, principals, access keys, KMS aliases/grants,
Lambda aliases, launch-template versions, launch configurations, SNS subscriptions,
DynamoDB GSIs, Elasticache topics, reserved-node/reserved-instance offerings,
`ECSContainerDefinition`, S3 ACLs/policy statements, Inspector findings, Config
recorders/delivery channels, Route53 record sets.

---

## 3. GCP

Mechanism: each module opts in by calling `label.sync_labels()` on already-fetched data
(no extra API calls). 47 call sites, 20 modules.

`label.py` carries an `OWNERSHIP_PATHS` map for resources owned by a parent resource
rather than directly by the project — without it the load query's
`(resource)<-[:RESOURCE]-(:GCPProject)` MATCH never fires and the labels are dropped.
Every entry needs a matching statement in `gcp_labels_cleanup.json`; a unit test asserts
that.

### 3.1 Working today (38 labels as `GCPLabel` nodes + 2 as property)

GCPInstance, GCPVpc, GCPProxy, GCPFunction, GCPComputeDisk, GCPKMSKeyRing,
GCPKMSCryptoKey, GCPLocation, GCPDNSZone, GCPServiceAccount, GCPRole,
GCPBigqueryDataset, GCPBigqueryTable, GCPBigtableInstance, GCPBackendBucket,
GCPBackendService, GCPUrlMap, GCPHealthCheck, GCPInstanceGroup, GCPSSLPolicy,
GCPMonitoringAlertPolicy, GCPMonitoringNotificationChannel,
GCPMonitoringUptimeCheckConfig, GCPDataprocCluster, GCPDataFlowJob, GCPPubsubTopic,
GCPPubsubSubscription, GCPSpannerInstance, GCPSpannerInstanceConfig,
GCPFirestoreDatabase, GCPBucket, GKECluster, GCPSQLInstance, Cloud Run ×6.

As a `labels` property (not nodes — invisible to inventory-sync's tag extraction):
GCPArtifactRegistryRepository, GCPContainerRegistryRepository.

### 3.2 Previously wired but broken (now fixed)

| Label | Bug | Fix |
|---|---|---|
| `GCPBucket` | `storage.py` rewrote `labels` into a list of tuples; `label.py` coerces non-dict to `{}` — GCS bucket labels silently lost | keep the dict |
| `GKECluster` | GKE API returns labels under `resourceLabels`; nothing remapped to `labels` | `cluster['labels'] = cluster.get('resourceLabels', {})` |
| `GCPSQLInstance` | Cloud SQL labels live at `settings.userLabels`; never lifted | same remap `cloudmonitoring.py` already did correctly |

These three are the most classification-relevant GCP resources (buckets = data
classification, GKE = app classification, Cloud SQL = both); the regression tests must
stay.

### 3.3 Not covered (~48) — what is actually left

The original version of this plan listed a dozen "high-value targets" that **do not
support labels at all**. Verified against the GCP API surface:

| Resource | Labels? | Action |
|---|---|---|
| GCPSubnet (`subnetworks`) | no | skip |
| GCPSpannerInstanceDatabase | no (labels live on the instance) | skip |
| GCPBigtableTable / Cluster / Backup | no (labels live on the instance) | skip |
| GKENodePool | no resource labels; `config.labels` are Kubernetes node labels, a different concept | skip |
| GCPCloudTasksQueue | no | skip |
| Pub/Sub Lite topics & subscriptions | no | skip |

Genuinely open:

- **GCPProject** — projects carry labels, and project-level labels would let
  classification cascade to every asset in the project. Needs its own anchor in
  `label.py`: the default path walks *to* `GCPProject`, so a project labeling itself
  cannot use it.
- **GCPArtifactRegistryRepository / GCPContainerRegistryRepository** — labels are already
  fetched and stored as a node property. Converting them to `GCPLabel` nodes needs both
  a `match_property` override (these nodes key on `name`, not `id`) and a decision about
  whether to renumber the node key; that is a schema change, not a one-line addition.
- **GCPForwardingRule** — labelable, but its node id is a `partial_uri` rather than the
  API `id`, and it attaches to either a subnet or a VPC. Needs a transform plus a
  two-branch ownership path; low classification value, so it sits behind the two above.

Not labelable / skip: bindings, ACLs, policy objects, record sets, DNS keys, IAM
users/groups/domains, service account keys, API keys, network tags (a different concept),
compute images (no `GCPImage` node exists).

Also: `cloudcdn.py` reads `resourceManagerTags` into a dead local — GCP **Resource
Manager tags** (the IAM-integrated key/value tags, distinct from labels) are captured
nowhere. Worth a separate look once labels are complete.

---

## 4. Azure

Mechanism is already generic (ARM crawl matching node `id` to ARM resource id) — best
architecture of the four; no per-type wiring needed. ~25 top-level ARM types get tags
today (VMs, VMSS, disks, snapshots, AKS, ACR, ACI, storage accounts, key vaults, SQL
servers, SQL databases, elastic pools, Cosmos accounts, function apps, networks, NSGs,
LBs, route tables, NAT/bastion, public IPs, NICs, managed identities, images, resource
groups).

Resolved:

1. **`AzureSQLDatabase` tags** are loaded from the SQL SDK's existing
   `databases.list_by_server` response (SQL databases are ARM child resources, so
   `tag.py`'s resource-group crawl never sees them).
2. **Case-sensitivity** — the attach used to require node `id` == ARM id *exactly*, so
   any module normalizing ids differently silently got no tags. Both sides are now
   compared lowercased, and the lowercased id is derived inside `_load_tags_tx` so every
   producer (including `sql._load_database_tags`) stays correct by construction.
3. **Traversal cost** — the ownership descent was an unbounded `-[*]->` over the whole
   subscription subgraph, evaluated per tag row. Now bounded at `-[*1..4]->`
   (subscription → resource group → resource → child is 3 hops). The worker pool is
   bounded at 8 and tag writes are batched.

Remaining: verify stale-tag cleanup for SQL databases in an integration run, and confirm
`*1..4` is deep enough for every tagged type (a type that sits deeper would go silently
untagged — the same failure mode the depth bound is meant to make cheap, not invisible).
The remaining ~69 labels are child/sub-resources that mostly cannot carry ARM tags.

---

## 5. OCI

OCI tag ingestion covers compute, network, storage, database, encryption, logging,
monitoring, container registry and OKE. The implementation uses a shared helper with
`OCITag` indexes and cleanup.

### 5.1 Current implementation (28 labels)

- Nearly every OCI API response already parsed carries `freeform_tags` and
  `defined_tags` — **no new API calls**, transform-layer change only.
- inventory-sync already ships the consumer: `ociinventoryviewhelper.py` passes the
  literal `"OCITag"`; the downstream pipeline needs no changes.
- Wired: OCIAutonomousDatabase, OCIBlockVolume, OCIBootVolume, OCIContainerRepository,
  OCIDbHome, OCIDbSystem, OCIEventRule, OCIFileSystem, OCIImage, OCIInstance,
  OCIInternetGateway, OCIKmsKey, OCIKmsVault, OCILog, OCILogGroup, OCIMonitoringAlarm,
  OCIMountTarget, OCINatGateway, OCINetworkSecurityGroup, OCINotificationTopic,
  OCIOKECluster, OCIOKENodePool, OCIRouteTable, OCISecurityList, OCIStorageBucket,
  OCISubnet, OCIVcn, OCIVolumeBackup.

Model (mirrors GCP's per-resource scheme, avoiding AWS's shared-node mistake):

```
(:OCITag {id: "<resource_ocid>/tag/<key>", key, value, firstseen, lastupdated})
(resource)-[:TAGGED]->(:OCITag)
```

- `freeform_tags` → `{key: value}` directly.
- `defined_tags` → namespaced: `{namespace.key: value}` (flatten
  `{"Operations": {"CostCenter": "42"}}` → key `"Operations.CostCenter"`). Namespaced
  keys flow through auto-classification's verbatim-match path like `eks:cluster-name`
  does today.

### 5.2 Nested ownership (was a confirmed defect, now fixed)

`intel/oci/tags.py` used to match a tagged resource only through a direct
`OCICompartment-[:RESOURCE]->resource` path. `OCIKmsKey` nodes connect to their
`OCIKmsVault` with `OCI_KMS_KEY` instead, so KMS key tags were fetched from OCI and
discarded — and the cleanup query carried the same assumption.

`tags.py` now carries an `OWNERSHIP_PATHS` map (label → Cypher fragment back to the
owning compartment) covering `OCIKmsKey`, `OCIDbHome`, `OCILog` and `OCIVolumeBackup`.
`oci_import_tags_cleanup.json` has a matching statement per path, and a unit test fails
if a path is added without one — a stale-edge path the cleanup cannot reach would keep
serving tags the provider already removed.

### 5.3 Not covered (~16)

- **OCIVnic** — taggable, but `load_vnics` attaches the VNIC to its subnet with an
  `OPTIONAL MATCH`, so a VNIC with no subnet edge has no ownership path at all. Wire it
  only after the attachment is made unconditional.
- **OCIUser / OCIGroup / OCIPolicy** — taggable, but they hang off `OCITenancy`, not off
  a compartment, so they need a second anchor in `tags.py` rather than an
  `OWNERSHIP_PATHS` entry.
- Not taggable: OCIDbNode, OCIContainerImage, volume/boot-volume/VNIC *attachments*,
  OCINsgSecurityRule, OCIFlowLog, OCIRegion, OCICompartment/OCITenancy themselves,
  OCICloudGuard, OCIAuditConfiguration, OCILoggingService/OCILoggingConfiguration.

---

## 6. Cross-cutting fixes required for classification correctness

Expanding coverage on a pipeline that silently drops or never expires tags degrades
classification quality, so these gate the coverage work rather than following it.

| # | Fix | Where | Status |
|---|---|---|---|
| C1 | Tag extraction by relationship, not `Labels(Node)[0]` — `AWSTag:Tag` double label + undefined Neo4j label order can silently drop ALL AWS tags | inventory-sync-aws `helpers/basehelper.py` + query projections | **open** |
| C2 | Complete `aws_import_tags_cleanup.json` (generic like Azure's) + fix the broken RedshiftCluster statement (duplicated workspace hop) | cartography | **done** |
| C3 | Producer-side shape assertion for `metadata.tags` (array of `{key,value}`) — the console's `jsonb_array_elements` path yields zero rows silently on the wrong shape | inventory-sync helpers | **open** |
| C4 | Emit `tags: []` for supported-but-untagged resources (stop `ignore_nulls` removing the key) so the console can tell "untagged" from "unsupported" | inventory-sync | **open** |
| C5 | Scope `AWSTag.id` per workspace/account (or at least document the shared-node semantics) — cross-tenant shared nodes, `region` last-writer-wins | cartography | **open** |
| C6 | Prune `d_tags` or filter dropdowns by `d_asset_tags` — the classification UI offers keys/values that no longer exist | cloudanix-web | **open** |
| C7 | Treat `iam:role` as a global AWS tag source — `get_role_tags()` is region-independent but ran once per region | cartography | **done** |
| C8 | Support nested OCI ownership paths in tag load and cleanup | cartography | **done** |
| C9 | Same nested-ownership support for GCP labels (`OWNERSHIP_PATHS` in `label.py` + cleanup statements) | cartography | **done** |

---

## 7. Prioritized plan

### Phase 0 — fix what's silently broken

| Item | Repo | Status |
|---|---|---|
| 3 GCP transform fixes: GCPBucket, GKECluster, GCPSQLInstance | cartography | done — keep the regression tests |
| C2 AWS cleanup completeness + broken Cypher | cartography | done |
| AWS nested mappings for ECS services/tasks, listeners, EKS node groups | cartography | done |
| C7 `iam:role` on the global-source path | cartography | done |
| C8 OCI nested ownership paths (KMS keys et al.) | cartography | done |
| C1 label-ordering fragility | inventory-sync-aws | **open** |

### Phase 1 — OCI coverage

Done: images, volume backups, database homes, log groups + logs, monitoring alarms,
event rules, notification topics, container repositories (28 labels total).
Remaining: `OCIVnic` (needs an unconditional subnet attachment) and the tenancy-anchored
IAM resources (§5.3). Each addition needs a loader call, a cleanup statement if its
ownership path is nested, and one graph-path test.

### Phase 2 — AWS mapping additions

Done: data stores (EBSSnapshot, EC2Image, RDS/EC2 reserved instances), workload identity
(CloudWatch alarms, EventBridge rules and buses, log groups, ECS services, EKS node
groups, SNS), edge (route tables, WAF v2 + classic, Route53 hosted zones, CloudFront,
launch templates), AI/ML (SageMaker ×6, Bedrock ×4), governance (CloudTrail, Config
rules, SES identities, Security Hub).

Remaining: `AWSPermissionSet` via the SSO Admin tagging API — a separate small fetcher
like `get_role_tags`, plus a `GLOBAL_RESOURCE_TYPES` entry since Identity Center is
region-pinned.

Each addition: one mapping row (+ `id_func` if the node uses a short id, + `path` if it
is a sub-resource) + a cleanup statement for a nested path + verify the label exists in
`config/inventory.aws.json`.

### Phase 3 — GCP `sync_labels` additions

Done: GCPComputeDisk, GCPKMSCryptoKey (via `OWNERSHIP_PATHS`).
Remaining, in value order: GCPProject labels (needs its own anchor), Artifact/Container
Registry repositories (property → nodes, needs a `match_property` override),
GCPForwardingRule. Everything else previously listed here is not labelable (§3.3).

### Phase 4 — Azure completeness

Done: AzureSQLDatabase tags, case-insensitive id match, bounded ownership traversal,
bounded worker pool, batched writes.
Remaining: integration-verify stale-tag cleanup for child resources, and confirm the
`*1..4` depth bound covers every tagged type.

### Phase 5 — console-side hygiene & insights

C4 untagged-vs-unsupported distinction → "untagged resources" coverage report per
account (tag hygiene is the #1 blocker for classification usefulness); C6 `d_tags`
pruning; extend `default_tag_mappings.yml` as new providers' native tag conventions
appear (e.g. OCI `Oracle-Tags.CreatedBy`, `oke-cluster-name`-style keys, Azure
`aks-managed-*` already present).

---

## 8. Validation and release gates

Before merging further tag changes:

1. Run provider unit tests plus graph-backed integration tests for one direct resource
   and one nested resource per provider.
2. Verify stale tag relationships are removed when a provider removes a tag — including
   for nested ownership paths, which need their own cleanup statement.
3. Verify a failed/permission-denied provider call does not unintentionally erase a
   prior tag set unless the sync explicitly marks that resource type as successfully
   refreshed.
4. Run the inventory extraction contract test and confirm `metadata.tags` is always an
   array of `{key, value}` objects.
5. **Audit every newly tagged node label against `config/inventory.<provider>.json`.**
   33 AWS labels and 9 OCI labels have been added since the last audit; any label missing
   from that config produces tags nobody reads.
6. Keep `design.md` and this plan aligned with the implemented state.

## 9. Classification lens — why these resources

**App classification** keys on tag keys like `app`, `service`, `project`, `env`, `team`
(see `authoring/classification/default_tag_mappings.yml` in cloudanix-web). Its
usefulness depends on covering the resources where teams *put* those tags: workloads
(ECS services ✓, EKS node groups ✓, GKE ✓, Cloud Run ✓, OKE ✓), stacks (CloudFormation ✓,
Azure resource groups ✓) and messaging (SNS ✓, Pub/Sub ✓, Kinesis ✓, OCI notification
topics ✓).

**Data classification** keys on `dataclassification`/`sensitivity`-style tags with values
pii/phi/confidential/internal/public. Its usefulness depends on covering the **data
stores**:

| Store | AWS | GCP | Azure | OCI |
|---|---|---|---|---|
| Object storage | S3 ✓ | GCS ✓ | storage accounts ✓ | buckets ✓ |
| Databases | RDS ✓ | Cloud SQL ✓ | SQL server ✓ / SQL DB ✓ | Autonomous ✓, DB systems ✓, DB homes ✓ |
| Disks & snapshots | EBS volume ✓ / snapshot ✓ | disk ✓ | disk ✓ / snapshot ✓ | block + boot volumes ✓, backups ✓ |
| Analytics | Redshift ✓ | BigQuery ✓ | Cosmos ✓ | — |
| Keys | KMS ✓ | KMS key ring ✓ / crypto key ✓ | key vault ✓ | vault ✓ / key ✓ |

The data-store row that motivated Phases 0–1 is now closed on all four providers. The
remaining classification risk has moved downstream: C1 (extraction can drop every AWS
tag on a label-order flip), C3/C4 (shape and untagged-vs-unsupported), and the
inventory-config audit in §8.5 — a tag written into the graph that no inventory config
reads is worth exactly as much as a tag never collected.
