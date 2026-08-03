# Tags Processing — End-to-End Design

How cloud resource tags/labels travel from cloud provider APIs into the Neo4j graph
(cartography), out through the inventory service (inventory-sync-aws), and into the
Cloudanix console (cloudanix-web) where they power app & data classification.

Repos referenced:

| Repo | Path | Role |
|---|---|---|
| cartography | `/Users/puru/code/cartography` | Syncs cloud resources + tags into Neo4j |
| inventory-sync-aws | `/Users/puru/code/inventory-sync-aws` | Reads graph, returns inventory payloads to console |
| cloudanix-web | `/Users/puru/code/cloudanix-web` | Console: stores tags in OLAP, drives classification |

---

## 1. Big picture

```
Cloud APIs                  Neo4j graph                    Inventory payload              Console OLAP
──────────                  ───────────                    ─────────────────              ────────────
AWS Resource Groups   ──►   (:AWSTag:Tag)◄─[:TAGGED]─      metadata.tags:                 d_asset_stagings.tags (jsonb)
  Tagging API               (:GCPLabel)◄─[:LABELED]─  ──►    [{key, value}, ...]    ──►   d_asset_tags (row per kv)
GCP labels (inline)         (:AzureTag)◄─[:TAGGED]─                                       d_tags (catalog)
Azure ARM resources         OCI: (nothing)                                                      │
OCI: (not collected)                                                                            ▼
                                                                                     classifications / d_classifications
                                                                                     mv_asset_classification
                                                                                     (app & data classification)
```

Three hand-offs:

1. **cartography** fetches tags per provider and writes tag nodes + relationships into Neo4j. Tag sync runs **last** in each account sync so resource nodes already exist.
2. **inventory-sync-aws** never queries tags explicitly. Its generic per-resource-type Cypher collects *all* neighbor nodes; Python then picks out neighbors whose label equals a hardcoded per-provider tag label (`AWSTag` / `GCPLabel` / `AzureTag` / `OCITag`) and emits `metadata.tags = [{key, value}]`.
3. **cloudanix-web** receives the payload on a webhook, stages it, shreds `metadata.tags` into `d_asset_tags` (one row per asset×key×value), and joins those rows against account-level classification mappings to derive app & data classification.

---

## 2. Stage 1 — cartography: tags into the graph

There is **no shared tag helper**; each provider has its own implementation, node label,
relationship name, and collection strategy. OCI collects nothing.

| Provider | Node label | Relationship | Node id format | Strategy |
|---|---|---|---|---|
| AWS | `AWSTag:Tag` | `(resource)-[:TAGGED]->(tag)` | `"<Key>:<Value>"` | Dedicated module, Resource Groups Tagging API, runs last |
| GCP | `GCPLabel` | `(resource)-[:LABELED]->(label)` | `"<resource_id>/label/<key>"` | Shared helper called per-service on already-fetched data |
| Azure | `AzureTag` | `(resource)-[:TAGGED]->(tag)` | `"<resource_id>/providers/Microsoft.Resources/tags/<key>"` | Dedicated module walking ARM resource groups, runs last |
| OCI | — | — | — | **None. `freeform_tags`/`defined_tags` dropped at ingestion.** |

### 2.1 AWS — `cartography/intel/aws/resourcegroupstaggingapi.py`

- **Fetch**: `get_tags()` (line 149) paginates `resourcegroupstaggingapi:get_resources`
  with `ResourceTypeFilters=[resource_type]`, one call sequence per (region × resource
  type). `iam:role` is not supported by that API, so it falls back to
  `iam.get_role_tags()` (`intel/aws/iam.py:210`), reading each role's tags individually.
  Exceptions per resource type are swallowed with a warning — a failing type silently
  yields zero tags.
- **Coverage**: `TAG_RESOURCE_TYPE_MAPPINGS` (line 76) — 48 resource-type filters mapping
  to 46 node labels (EC2Instance, S3Bucket, RDSInstance, AWSLambda, EKSCluster, AWSRole,
  KMSKey, SQSQueue, …). Each entry: `{label, property, id_func?}` where `id_func`
  converts ARN → cartography's short id (EC2, S3, ELB, ALB/NLB).
- **Load**: `_load_tags_tx` (line 173). Template query — labels can't be Cypher
  parameters, so `$resource_label`/`$property` are string-substituted:

  ```cypher
  UNWIND $TagData as tag_mapping
      UNWIND tag_mapping.Tags as input_tag
          MATCH (a:AWSAccount{id:$Account})-[res:RESOURCE]->(resource:<label>{<property>:tag_mapping.resource_id})
          MERGE (aws_tag:AWSTag:Tag{id:input_tag.Key + ":" + input_tag.Value})
          SET aws_tag.key = input_tag.Key, aws_tag.value = input_tag.Value, aws_tag.region = $Region, ...
          MERGE (resource)-[r:TAGGED]->(aws_tag)
  ```

  The `MATCH` means tags attach only to resources that already exist — hence sync order.
  Note: `id = key:value` with no account scoping, so one tag node is **shared across all
  accounts/resources** in the graph; `region` is last-writer-wins.
- **Sync order**: registered as the **last** entry of `RESOURCE_FUNCTIONS`
  (`intel/aws/resources.py:113`); explicitly excluded from the sequential and parallel
  service loops and invoked at the very end of `_sync_one_account`
  (`intel/aws/__init__.py:258`, "AWS Tags - Must always be last"). It is the only sync
  called with `config` as an extra arg. In non-local runs it fans out a
  `ThreadPoolExecutor` task per (region × resource type), each with its own boto3
  session and Neo4j driver.
- **Cleanup**: `aws_import_tags_cleanup.json` — per-type stale-relationship statements
  cover only ~10 of the 48 types; the catch-all only deletes fully orphaned tag nodes.
  So stale `TAGGED` edges persist on the other ~38 types (see §6).

### 2.2 GCP — `cartography/intel/gcp/label.py`

- Shared helper, not a sync module. Each service module calls
  `label.sync_labels(session, data, update_tag, common_job_parameters, service_name, service_label)`
  (line 89) on the resource list it already fetched — labels come from the `labels`
  field of the existing API payload, **zero extra API calls**.
- `get_labels_list()` flattens `item['labels']` into
  `{id: "<resource_id>/label/<key>", key, value, resource_id}`. `_load_labels_tx`
  (line 58) MERGEs `GCPLabel` and creates `(resource)-[:LABELED]->(label)` scoped
  through `GCPProject ← GCPOrganization ← CloudanixWorkspace`. Label nodes are
  **per-resource** (id embeds resource id), unlike AWS.
- **46 call sites across 20 service modules**: compute (GCPInstance, GCPVpc, GCPProxy),
  storage (GCPBucket), gke (GKECluster), sql, bigquery (dataset + table), cloudfunction,
  cloudrun (6 node types), iam (service accounts, roles), kms, dns, pubsub, spanner,
  bigtable, dataflow, dataproc, firestore, cloudmonitoring, apigateway, cloudcdn,
  loadbalancer.
- Cleanup: each `service_label` is appended to
  `common_job_parameters['service_labels']`; after all services run,
  `gcp/__init__.py:756` loops the list calling `label.cleanup_labels` →
  `gcp_labels_cleanup.json`.
- Distinct concept: `GCPNetworkTag` (`compute.py:1396`) models GCE **network tags**
  (firewall targeting), rel `TAGGED`/`TARGET_TAG` — not key/value metadata; do not
  confuse with `GCPLabel`. `GCPBucketLabel` is legacy/dead (index + cleanup remain, no
  writer).

### 2.3 Azure — `cartography/intel/azure/tag.py`

- `sync()` lists ARM resource groups (`ResourceManagementClient`), creates
  `AzureResourceGroup` nodes, then `sync_tags()` fans out over the resource groups on a
  pool bounded at 8 workers. Each thread collects the group's own `tags` dict plus the
  `tags` of every resource in `list_by_resource_group`. There is no per-resource
  existence probe: the load query MATCHes the resource before MERGEing the tag, so
  resources absent from the graph produce nothing and cost no extra round trip.
- Load (`_load_tags_tx`): MATCH the owning subscription, descend
  `-[*1..4]->(l) WHERE toLower(l.id) = tag.resource_id_lower`, then MERGE the
  `AzureTag{id: "<resource_id>/.../tags/<key>"}` and `(l)-[:TAGGED]->(t)`. Writes are
  batched 500 at a time. The lowercased id is derived inside `_load_tags_tx`, so every
  producer of tag rows (including `sql._load_database_tags`) is case-correct by
  construction — ARM ids are case-insensitive, and modules normalize them inconsistently.
- **Coverage is id-driven, not type-driven**: any Azure node whose `id` matches a
  top-level ARM resource id (case-insensitively) gets tagged. Sub-resources with
  composite ids are invisible to this crawl and need their own harvest — `AzureSQLDatabase`
  does exactly that off the `databases.list_by_server` payload in `intel/azure/sql.py`.
- Called directly at `intel/azure/__init__.py:237`, after all services, with the comment
  "call tag.sync() at the last, don't change position of tag.sync()".
- Cleanup: `azure_import_tags_cleanup.json` is generic (matches any `(m)` via `-[*]->`)
  — covers all tagged types, unlike AWS.

### 2.4 OCI — `cartography/intel/oci/tags.py`

- Modeled on GCP's `label.py`: each service module calls `tags.sync_tags()` on the raw
  (hyphen-keyed) API payload it already fetched, so tag ingestion adds **no extra API
  calls**. 28 call sites across 9 modules today.
- `get_tags_list()` flattens both tag kinds off each raw dict: `freeform-tags` verbatim,
  `defined-tags` namespaced as `<namespace>.<key>` (so
  `{"Operations": {"CostCenter": "42"}}` becomes key `Operations.CostCenter`). Items
  without an `id` are skipped; values are stringified.
- Load (`_load_tags_tx`): MATCH the resource, walk back to its owning `OCICompartment`,
  then up through `OCITenancy` and `CloudanixWorkspace`, and only then MERGE the
  `OCITag` and the `TAGGED` edge — so tags for resources absent from the graph create no
  orphan nodes. Writes are batched 500 at a time.
- The walk back to the compartment is `<-[:RESOURCE]-` by default. Resources owned by a
  parent resource (`OCIKmsKey` under its vault, `OCIDbHome` under its DB system, `OCILog`
  under its log group, `OCIVolumeBackup` under its volume) declare their path in
  `OWNERSHIP_PATHS`; without it a direct-only MATCH silently drops their tags.
- Cleanup: `oci_import_tags_cleanup.json` has one stale-relationship statement per
  ownership path plus an orphan-node catch-all. A unit test fails if an `OWNERSHIP_PATHS`
  entry has no matching statement.

### 2.5 Graph schema summary

```
AWS:   (:AWSTag:Tag {id:"<key>:<value>", key, value, region, firstseen, lastupdated})
       (resource)-[:TAGGED]->(:AWSTag)          indexes: AWSTag(id), AWSTag(key)
GCP:   (:GCPLabel {id:"<rid>/label/<key>", key, value, ...})
       (resource)-[:LABELED]->(:GCPLabel)       no index on GCPLabel
Azure: (:AzureTag {id:"<rid>/providers/Microsoft.Resources/tags/<key>", key, value,
                   type:"Microsoft.Resources/tags", region:"global", resource_group, ...})
       (resource)-[:TAGGED]->(:AzureTag)        index: AzureTag(id)
OCI:   (:OCITag {id:"<ocid>/tag/<key>", key, value, firstseen, lastupdated})
       (resource)-[:TAGGED]->(:OCITag)          index: OCITag(id)
```

---

## 3. Stage 2 — inventory-sync-aws: tags out of the graph

### 3.1 Entry points

Queue workers, not an API — deployed per cloud as AWS Lambda / GCP Cloud Function /
Azure Function:

| Cloud | Entrypoint | Request in | Result out |
|---|---|---|---|
| AWS | `aws.py:137` `process_handler` | SNS (`aws_inventory_request_topic`) | SNS (`aws_inventory_views_response_topic`) |
| GCP | `main.py:135/:175` | PubSub | PubSub |
| Azure | `azure.py:160` | EventGrid | EventGrid |

If the request sets `inventoryRefresh`, it is first routed to the cartography SQS queue
(`handlers/requesthandler.py:281`) so the graph is refreshed before being read. The
worker dispatches `templateType == AWSINVENTORYVIEWS` →
`AWSInventoryViewsHandler.process_views`; the only rule is
`{"list_resources": fetch_list_resources}` (`handlers/awsinventoryviewshandler.py:112`).
Oversized results are stored in S3 and only `{"S3uri", "sessionString"}` published
(`libraries/snslibrary.py:71`).

### 3.2 How tags are read — implicitly

**There is no tag-specific Cypher anywhere.** Every resource type's query
(`helpers/awsinventoryviewshelper.py:117-132`, mirrored in the gcp/azure/oci helpers —
24 call sites) projects all neighbors:

```cypher
MATCH (cw:CloudanixWorkspace{id:'<ws>'})-[...]->(aa:AWSAccount{id:'<acct>'})<path>(n:<Label>)
WITH distinct n
OPTIONAL MATCH (n)-[Relation]-(Node) WHERE Node is not null
WITH n, collect({
    nodeProperties: properties(Node),
    nodeLabel: [x IN Labels(Node) WHERE not x in [...]][0],
    relationName: type(Relation),
    direction: ...,
    key: Node.key, value: Node.value        -- ← the entire tag read path
}) as relationships
RETURN ...
```

`key`/`value` are blindly projected off every neighbor node; non-tag neighbors yield
nulls there. Which resource types are queried at all comes from
`config/inventory.<provider>.json` (89 AWS / 70 GCP / 62 Azure / 42 OCI node types —
`{fields, node, path, service}`); **none of these configs mention tags** — tag coverage
is decided entirely by what cartography wrote to the graph. Tags ride along in the same
query, so there is no N+1.

### 3.3 Extraction & normalization — `helpers/basehelper.py:325-356`

`process_fields` walks each entity's `relationships`; a neighbor whose `nodeLabel`
equals the per-provider tag literal becomes a tag, everything else a relationship:

| Provider | Literal passed | Matches graph node |
|---|---|---|
| AWS | `"AWSTag"` (`awsinventoryviewshelper.py:89,151`) | `AWSTag:Tag` ✓ |
| GCP | `"GCPLabel"` (`gcpinventoryviewshelper.py:95,175`) | `GCPLabel` ✓ |
| Azure | `"AzureTag"` (`azureinventoryviewshelper.py:106,150`) | `AzureTag` ✓ |
| OCI | `"OCITag"` (`ociinventoryviewhelper.py:107,151`) | **nothing — node doesn't exist** |

Normalization is minimal: drop entries with null key or value, wrap as
`{"key": ..., "value": ...}`. No case folding, no dedup, no `aws:*` filtering.
`ignore_nulls` then strips empty keys, so an untagged resource has **no `tags` key at
all** — the console cannot distinguish "untagged" from "type not supported".

### 3.4 Output shape

```json
{
  "status": "success",
  "params": {"templateType": "...", "eventId": "...", "sessionString": "...", "workspace": {...}},
  "response": {"findings": [{
      "rule": "list_resources", "status": "success",
      "resources": {"aws-compute-ec2-instance": {"data": [{
          "id": "i-0abc", "uniqueId": "i-0abc", "name": "web-1",
          "consoleLink": "...", "region": "us-east-1", "updatedOn": 1609271048,
          "metadata": {"instanceType": "t3.medium",
                       "tags": [{"key": "Env", "value": "prod"}]},
          "relationships": [ ... ]
      }]}}
  }]}
}
```

Tags always live at **`metadata.tags`** (the `common_attributes` allowlist at
`basehelper.py:13` routes only id/name/region/etc. to the root).

---

## 4. Stage 3 — cloudanix-web: tags into OLAP & classification

### 4.1 Ingestion

Push model. Console kicks off scans (`app/runner/base_runner.rb:4` → HTTP POST to the
template endpoint) and receives results on webhooks
(`POST /v1/awswebhook/template_handler` and siblings, `config/routes.rb:1122+`):

```
awswebhook_controller#template_handler
  → StageIncoming.stage/handler
  → IncomingAws.handler (app/domains/aws/incoming_aws.rb:7)
  → BaseRunner.save_inventory_message → Inventory.save_webhook_response (app/models/inventory.rb:97)
      · stores blob in OLTP inventories.json_object (jsonb)
      · InventoryHasher change detection (identical payload within 30d ⇒ ELT skipped)
      · fires DataSyncHandler.sync("INVENTORYSYNC")
```

The load-bearing contract is a Postgres composite type (`db/olap_structure.sql:157`):

```sql
CREATE TYPE public.inventory_json AS (
    id varchar, name varchar, region varchar, metadata json,
    "uniqueId" varchar, "updatedOn" bigint, "consoleLink" varchar,
    "isPublicFacing" boolean, "isActive" boolean, relationships json
);
```

`DAssetStaging::ELT.stage_inventory_v2` (`app/models/d_asset_staging.rb:109`) runs
`json_populate_recordset(null::inventory_json, data)` and lifts
`(inv_data).metadata->'tags'` into `d_asset_stagings.tags jsonb`.

### 4.2 Storage

| Table | Shape | Semantics |
|---|---|---|
| `d_asset_stagings.tags` | jsonb array of `{key,value}` | per-session staging |
| `d_asset_tags` | row per (asset, key, value): `key, value, key_lower, value_lower, source ('INVENTORY'\|'CONSOLE')` | **live truth**; unique on `(account_id, entity_id, asset_id, key_lower, value_lower)` |
| `d_tags` | distinct `(account_id, key, value)` catalog | powers UI dropdowns; **append-only, never pruned** |
| `d_assets.tag_count` | int | denormalized counter |

Sync (`InventoryElt.dsf_elt_asset_tags`, `app/elt/inventory_elt.rb:221`):
1. `DAssetTag::ELT.sync_tags` — delete all `source='INVENTORY'` rows for the
   account/entity, reinsert from staging via `jsonb_array_elements(das.tags)` (delete +
   reinsert is why cloud-removed tags actually disappear).
2. `DTag::ELT.sync_tags` — append-only insert into `d_tags`.
3. `DAsset::ELT.update_tag_count`.
4. If enabled: auto-classification `Classification.deduce_for_account`.
5. Delayed (60 min) `REFRESH MATERIALIZED VIEW mv_asset_classification`.

Console-authored tags: `DAssetTag.update_tags` writes `source='CONSOLE'` rows (asset
settings API, `code_api_request_handler.rb:1564`).

### 4.3 App & data classification

Classification = **account-level mapping from tag key (and optionally value) →
classification type**; assets inherit it by carrying a matching tag.

- Types: `m_classification_types` → `d_classification_types`. Area `application`
  (application, business_unit, application_owner, environment, business_criticality;
  key-match only) and area `data` (pii, phi, confidential, internal, public;
  value-match, `values_required: true`).
- Mappings: OLTP `classifications` (`key`, `values jsonb`, `source
  'user'|'cloudanix'|...`, `state`), synced to OLAP `d_classifications`.
- Join: `mv_asset_classification` (`olap_structure.sql:23194`) =
  `d_asset_tags ⋈ d_classifications_vw ⋈ d_classification_types`, aggregated to a jsonb
  array per asset.
- Auto-classification (shipped 2026-07): `Classification.deduce_for_account`
  (`app/models/classification.rb:30`) matches distinct account tag keys/values against
  the curated YAML `authoring/classification/default_tag_mappings.yml` (normalize:
  lowercase, strip `-_ .`; namespaced tags like `eks:cluster-name` matched verbatim),
  inserting `source='cloudanix'` rows without touching user rows or rejected
  tombstones. Spec:
  `docs/agent-specs-and-tasks/app-data-auto-classification/spec.md` (cloudanix-web).

Other tag consumers:
- **Security Graph**: `DGraphRelationship::ELT.upsert_tag_based_relations`
  (`d_graph_relationship.rb:801`) creates `TAGS`-type asset↔asset edges grouping assets
  that share a value on application-mapped tag keys.
- **Apps (legacy)**: `AppElt.sync_tags_begin` materializes `d_apps` /
  `d_apps_entities` / `f_apps_assets` from `d_tags` keys.
- **Filters/UI**: tag filter + has-tags filter + app/data classification filters
  (`api_filter_view.rb`, `dynamic_query_builder.rb`), asset-detail classification pane,
  `/classification` page, event correlation rule `resource_tag_match_rule.rb`.

---

## 5. End-to-end sequence (AWS example)

1. Console `BaseRunner.start_run` POSTs an `AWSINVENTORYVIEWS` request (with
   `inventoryRefresh`) to the inventory endpoint.
2. inventory-sync listener publishes to the cartography SQS queue; cartography runs
   `_sync_one_account`, all services first, `resourcegroupstaggingapi.sync` **last** —
   `TAGGED` edges land in Neo4j.
3. Worker resumes: per node type in `config/inventory.aws.json`, one Cypher query pulls
   the resource + all neighbors; `process_fields` extracts neighbors labeled `AWSTag`
   into `metadata.tags`.
4. Result published to SNS (S3-offloaded if big); console webhook stages it,
   `stage_inventory_v2` shreds `metadata.tags` → `d_asset_stagings.tags` →
   `d_asset_tags` (+ `d_tags` catalog).
5. `Classification.deduce_for_account` and/or user mappings on `/classification` join
   against `d_asset_tags`; `mv_asset_classification` refreshes; asset pages, filters,
   insights, and the security graph show app & data classification.

---

## 6. Known weaknesses in the current pipeline

Found during this analysis; each affects tag freshness/correctness and therefore
classification quality. (Remediation plan in [plan.md](./plan.md).)

1. **OCI: no tags at all.** Dropped at cartography ingestion; `"OCITag"` literal in
   inventory-sync matches nothing; OCI assets can never be classified via tags.
2. **AWS tag coverage gap.** 48 of the 89 AWS inventory node types can never return
   tags (only 41 intersect `TAG_RESOURCE_TYPE_MAPPINGS`). Notable misses: SNS topics,
   Kinesis, CloudFront, CloudTrail, CloudFormation stacks, Route53, ECS services, EKS
   node groups, EBS snapshots, WAF ACLs, Sagemaker, Bedrock. (Full lists in
   `plan.md`.)
3. **AWS label-ordering fragility.** Tag nodes carry two labels (`AWSTag:Tag`);
   inventory-sync derives `nodeLabel` as `Labels(Node)[0]`, and Neo4j does not
   guarantee label order. If `Tag` sorts first, every AWS tag is silently dropped.
   Fix: match `tag_label IN Labels(Node)` or `relationName = 'TAGGED'`.
4. **AWS cleanup gap.** `aws_import_tags_cleanup.json` covers ~10/48 types; stale
   `TAGGED` edges persist on the rest, so tags deleted in AWS can linger in the console
   indefinitely. Also a broken Cypher statement (duplicated `CloudanixWorkspace` hop)
   makes the RedshiftCluster cleanup unmatchable (line 44).
5. **AWS shared tag nodes.** `AWSTag.id = "<key>:<value>"` is unscoped — one node shared
   across all accounts and workspaces; `region` property is last-writer-wins.
6. **Wasted AWS tag writes.** Cartography tags `AWSLambdaLayer`,
   `AWSLambdaEventSourceMapping`, `AWSTransitGatewayAttachment`, `ECSContainer`,
   `ECSContainerInstance`, but these are not inventory node types — written, never read.
7. **Six AWS mappings wired but broken.** `ECSTask`, `ECSTaskDefinition`,
   `ECSContainer`, `ECSContainerInstance` hang off `ECSCluster` (not directly off the
   account), and `ELBListener`/`ELBV2Listener` hang off their load balancer — the load
   query's direct `(:AWSAccount)-[:RESOURCE]->` MATCH never fires (listeners also lack
   the `name` property the mapping keys on). Tag data is fetched from AWS every sync
   and silently dropped.
8. **Three GCP label call sites wired but broken.** `GCPBucket` (`storage.py:87`
   rewrites the labels dict into a list of tuples, which `label.py:20` coerces to `{}`),
   `GKECluster` (GKE API returns labels as `resourceLabels`, never remapped),
   `GCPSQLInstance` (labels live at `settings.userLabels`, never lifted). GCS buckets,
   GKE clusters, and Cloud SQL — three of the most classification-relevant GCP types —
   currently produce zero labels.
9. **Azure sub-resources untagged.** Id-driven matching only reaches top-level ARM
   resources; blob containers, SQL databases, key vault secrets etc. never match.
   Azure tag sync also does one Neo4j round trip per resource and uses unbounded
   `-[*]->` traversals — a performance risk at scale.
10. **Silent-failure contract.** Console-side `jsonb_array_elements` on
    `metadata.tags` yields zero rows for any shape other than an array of lowercase
    `{key, value}` objects — no error anywhere. Producer-side shape assertion is
    warranted.
11. **`d_tags` append-only.** Classification dropdowns keep offering keys/values that no
    longer exist anywhere; only `d_asset_tags` reflects reality.
12. **Untagged vs unsupported indistinguishable.** `ignore_nulls` removes the `tags`
    key entirely when empty, so the console can't tell "resource has no tags" from
    "tag collection not implemented for this type".
