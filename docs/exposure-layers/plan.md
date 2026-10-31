# Exposure layers: public, reachable, accessible, exploitable, blast radius

Status: implemented on branch `feat/exposure-layers` (see section 10). Covers AWS, GCP, Azure, OCI.
Constraint: no new cloud-provider services (no Inspector, Security Hub, Defender, SCC) and no
customer-facing probing. Everything is computed from the read-only API access the customer already
granted, plus public vulnerability intelligence.

## 1. Why

Today `exposed_internet` / `exposed_internet_type` mixes two different questions into one flag:
"does the resource have an internet-facing address" and "can internet traffic actually get to it".
That produces false positives (public IP behind a closed NACL, `PubliclyAccessible` RDS in a subnet
with no IGW route) and false negatives (private instance behind an internet-facing ALB). It also
says nothing about whether the thing answers without credentials or has a remotely exploitable flaw
on the exposed port, which is what decides priority.

Analogy: a house. Public = it has a front door on the street. Reachable = the gate, the fence and
the door are all open. Accessible = the door is not locked. Exploitable = there is a known way to
break the lock that burglars are using. Blast radius = what is inside.

## 2. Layers

| # | Layer | Question | Computed from | Owner |
|---|---|---|---|---|
| L1 | Public | Does config give it an internet-facing identity? | single-resource config | cartography (exists) |
| L2 | Reachable | Does a full allowed path exist from a source to a port? | network config graph walk | cartography |
| L3 | Accessible | Does it answer without credentials? | control-plane auth config | cartography |
| L4 | Exploitable | Is there a network-exploitable, actively exploited CVE on a reachable port? | L2 ports + software version + CVE data | cartography emits facts, **cloudanix-web joins CVEs** |
| L5 | Blast radius | What can it reach / act on if compromised? | IAM + internal L2 + data classification | cartography |
| L6 | Validated | Does it really respond? | active probing | **out of scope** (needs consent) |

A resource's priority rises with every layer that holds. All five holding is a "toxic combination".

### Ownership split for L4

```
 cartography (neo4j)                            cloudanix-web
 ---------------------------------------        ------------------------------------------
 per resource:                                  CVE DB (+ KEV, EPSS, EOL feeds)
   software_identity  (product, version)  --->  match identity -> CVEs
   reachable_ports    (proto:port list)   --->  keep CVEs with AV:N
   auth_state         (none|required|unknown)   keep CVEs whose service port is in reachable_ports
   blast radius facts                           score = f(L1..L5, KEV, EPSS, severity)
                     (via existing ELT/OLAP?)   re-score on feed change, no cloud re-sync needed
```

Reasons: CVE data already lives in cloudanix-web; feeds change on their own cadence (a new KEV entry
must re-score without waiting for a cloud sync); no second copy of the vuln DB in neo4j. Cartography
stays a fact collector, graph traversals stay in the graph.

## 3. Output schema (cartography side)

New properties, kept separate from the existing flag so current consumers are unaffected.

| Property | Type | Meaning |
|---|---|---|
| `exposed_internet` / `exposed_internet_type` | existing | unchanged during migration; later redefined as L1 AND L2 |
| `public_reasons` | list[str] | L1 reasons (`public_ip`, `public_endpoint`, `public_policy`, `internet_lb`, ...) |
| `internet_reachable` | bool | L2: a full path from `0.0.0.0/0` or `::/0` exists |
| `internet_reachable_ports` | list[str] | `<proto>:<from>-<to>` after intersecting every hop |
| `internet_reachable_via` | list[str] | path entry points (`igw:<id>`, `alb:<arn>`, `apigw:<id>`) |
| `access_auth` | str | L3: `none`, `required`, `unknown` |
| `access_auth_reasons` | list[str] | e.g. `lambda_url_auth_none`, `apigw_method_no_auth`, `gcs_allusers` |
| `software_identity` | list[str] | L4 input, normalized `<product>@<version>` (vocabulary: see open question 1) |
| `software_identity_source` | str | `managed_config` (high confidence), `image_name` (low), `scanner` |

Blast radius (L5) stays as relationships, not flattened properties: existing IAM permission
relationships plus new internal-reachability edges (section 6).

`internet_reachable_ports` is an upper bound. Config shows what is opened, not what is listening.

## 4. L2 reachability model

Per cloud, walk inbound hops in order. A port survives only if every hop allows it. Stateful vs
stateless matters: NACLs and OCI stateless security list rules need the return path allowed too.

```
AWS    internet -> IGW -> subnet route table (0.0.0.0/0 -> igw) -> NACL (in + ephemeral out)
              -> [ELB/ALB/NLB listener -> rule -> target group -> healthy target] -> SG -> ENI:port
              -> [API GW / CloudFront / Function URL: managed edge, path is implicit]
Azure  internet -> public IP | LB frontend + rule | App Gateway listener | Azure Firewall DNAT
              -> subnet NSG -> NIC NSG -> port          (route table: UDR 0.0.0.0/0 to NVA breaks path)
GCP    internet -> external IP (accessConfig) | forwarding rule -> backend service
              -> hierarchical firewall policy -> VPC firewall (priority, target tag / SA) -> port
              -> [Cloud Run / Functions: ingress setting]
OCI    internet -> IGW -> route table -> security list + NSG (stateful/stateless) -> VNIC:port
              -> [LB listener -> backend set]
```

Implementation shape (as built): a Python package per cloud, not JSON jobs. Cypher reads the facts
(subnets, routes, filters, attachments) for one account; pure Python evaluates port sets, so NACL /
NSG rule ordering and stateless return paths are unit-testable; one UNWIND write per label. Port-range
algebra in Cypher would be unreadable at 3am.

Known permanent blind spots (document in the UI, do not pretend): host firewalls (iptables, Windows
Firewall), services not actually listening on an opened port, NVA / third-party firewall appliances.

## 5. Gap audit

Method: grep of `cartography/intel/<cloud>` for the API calls and fields each layer needs. This is a
first pass; confirm each "missing" before building (a field may arrive under a different name).

Legend: Y = ingested, P = partially, N = not ingested.

### 5.1 AWS

| Need | Layer | State | Where / note |
|---|---|---|---|
| Security groups (in + out, ports) | L2 | Y | `ec2/security_groups.py` |
| Internet gateways | L2 | Y | `ec2/internet_gateways.py` |
| Route tables (+ NAT, TGW, peering targets) | L2 | Y | `ec2/route_tables.py`; used by subnet / ELB / ASG / RDS jobs, not by the instance job |
| Network ACLs | L2 | **Y (new)** | `ec2/network_acls.py`, sync key `ec2:network_acl` |
| **VPC endpoints** (S3 / service policies `aws:SourceVpce`) | L2/L3 | **N** | only referenced in `redshift.py` |
| Egress-only IGW, VPN gateway | L2 | N | needed for IPv6 and on-prem sources |
| ELBv2 listeners, target groups, target health | L2 | Y | `ec2/load_balancer_v2s.py` |
| **ALB listener rules** (path routing, `authenticate-oidc/cognito`) | L2/L3 | **N** | no `describe_rules` |
| Network Firewall | L2 | N | |
| WAF web ACLs | L4 (mitigation) | Y | `waf.py`, `cloudfront.py` |
| EKS endpoint public + `publicAccessCidrs` | L2 | Y | `eks.py` |
| Lambda function URL `AuthType` | L3 | Y | `lambda_function.py` |
| API Gateway method `authorizationType`, API key | L3 | **Y (new)** | `get_resources(embed=methods)`, same call; authorizer details still N |
| S3 policy / ACL public | L3 | Y | existing `aws_s3_asset_exposure` |
| Public snapshots / AMIs / RDS snapshots | L3 | Y | `ec2/snapshots.py`, `rds.py` (`describe_db_snapshot_attributes`) |
| OpenSearch domain policy + FGAC | L3 | P | version + policy present; advanced security options not seen |
| ElastiCache engine, version, port, AUTH token, transit encryption | L3/L4 | **Y (new)** | `ShowCacheNodeInfo=True` on the same call; Redis RBAC user groups still N |
| RDS engine + version, port | L4 | Y | `rds.py` |
| Redshift port | L4 | Y | `redshift.py`; cluster version not ingested (revision number only) |
| OpenSearch / Elasticsearch version | L4 | Y | `elasticsearch.py` |
| Lambda runtime | L4 | Y | `lambda_function.py` |
| EKS Kubernetes version | L4 | Y | `models/aws/eks/clusters.py` `version` |
| ENI IPv6 addresses | L1/L2 | **Y (new)** | `ipv6_addresses` on `NetworkInterface` |
| EMR release label | L4 | N | |
| AMI name / location / description (OS + age heuristic) | L4 | Y | `ec2/images.py` |
| **ECS task definition `portMappings`** | L4 (port alignment) | **N** | task defs ingested, port mappings not |
| ELB SSL policy | L4 | Y | `SslPolicy` in `load_balancer_v2s.py` |
| CloudFront minimum TLS | L4 | N | |
| Instance profile / Lambda role / task role | L5 | Y | existing IAM relationships |

### 5.2 Azure

| Need | Layer | State | Where / note |
|---|---|---|---|
| NSGs + security rules | L2 | Y | `network.py` |
| Route tables (UDR) | L2 | Y | `network.py`; no exposure job uses them yet |
| Public IP addresses | L1/L2 | Y | `network.py`, `compute.py`, `sql.py` |
| Load balancer frontends, LB rules, inbound NAT rules | L2 | Y | `network.py`, `compute.py` |
| **Application Gateway** (listeners, backend pools, WAF) | L2/L3 | **N** | |
| **Azure Firewall** (DNAT rules) | L2 | **N** | |
| Effective NSG / effective routes | L2 | N | optional shortcut; per-NIC API calls are expensive, compute it ourselves instead |
| Private endpoints | L2 | Y | `network.py`, `sql.py`, `cosmosdb.py` |
| `public_network_access` / network rule sets | L2/L3 | Y | storage, cosmosdb, ACR, function app, AKS |
| SQL / Cosmos firewall rules, function app IP restrictions | L2 | Y | `sql.py`, `cosmosdb.py`, `function_app.py` |
| AKS `api_server_access_profile` (authorized IPs, private) | L2 | Y | `aks.py` |
| Storage `allow_blob_public_access` + container access level | L3 | Y | `storage.py` |
| **App Service / Function auth settings (Easy Auth)** | L3 | **N** | |
| **SQL Azure AD only auth, `disable_local_auth`** (Cosmos, Service Bus, ...) | L3 | **N** | |
| **AKS Kubernetes version** | L4 | **N** | |
| VM image reference (publisher / offer / sku / version) | L4 | Y | `compute.py` |
| SQL server version, function app runtime stack | L4 | verify | |
| Minimum TLS version (storage, SQL, app service) | L4 | N | |
| Managed identities on VMs / apps | L5 | Y | `compute.py`, `iam.py` |

### 5.3 GCP

| Need | Layer | State | Where / note |
|---|---|---|---|
| VPC firewall rules | L2 | Y | `compute.py` |
| **Hierarchical / network firewall policies** | L2 | **N** | evaluated before VPC rules; missing them means wrong answers in orgs that use them |
| **VPC routes** (default internet gateway route) | L2 | **N** | only Cloud Run references routes |
| Instance external IPs (`accessConfigs`) | L1/L2 | Y | `compute.py` |
| Forwarding rules, backend services, URL maps, target proxies | L2 | Y | `compute.py`, `loadbalancer.py`, `cloudcdn.py` |
| **Cloud Armor security policies** | L4 (mitigation) | **N** | |
| **IAP on backend services** | L3 | **N** | IAP-protected = auth required |
| Cloud Run / Functions ingress setting | L2 | Y | `cloudfunction.py` (verify Cloud Run) |
| Cloud Run / Functions `allUsers` invoker | L3 | P | `allUsers` handled for storage, bigquery, iam; confirm for run / functions |
| GCS `allUsers`, public access prevention | L3 | Y | `storage.py` |
| GKE master authorized networks, private cluster | L2 | Y | `gke.py` |
| GKE master version | L4 | Y | `gke.py` |
| Cloud SQL `databaseVersion`, `authorizedNetworks`, `ipv4Enabled` | L2/L4 | Y | `sql.py` |
| Cloud Functions runtime | L4 | Y | `cloudfunction.py` |
| Instance source image / licenses (OS heuristic) | L4 | Y | `compute.py`, `images.py` |
| Instance service accounts + scopes | L5 | Y | `compute.py`, `iam.py` |
| Exposure jobs | all | P | only `gcp_gke_asset_exposure` and `gcp_load_balancer_exposure` write `exposed_internet`; compute instance, SQL, functions jobs exist under `analysis/` but use other flags. Verify. |

### 5.4 OCI

| Need | Layer | State | Where / note |
|---|---|---|---|
| Security lists (ingress rules, stateless flag) | L2 | Y | `network.py` |
| NSGs + rules | L2 | Y | `network.py`, used by LB, DB, OKE, API GW |
| Route tables, internet gateway, NAT gateway | L2 | Y | `network.py`; used by `oci_subnet_asset_exposure` |
| **Service gateway, DRG, local peering** | L2 | **N** | needed for internal / on-prem sources (L5), not for internet |
| VNIC public IP, `prohibit_public_ip_on_vnic` | L1/L2 | Y | `network.py`, `compute.py` |
| LB listeners, backend sets | L2 | Y | `load_balancer.py` |
| **WAF policies, Network Firewall** | L2/L4 | **N** | |
| ADB whitelisted IPs, private endpoint | L2 | Y | `database.py` |
| OKE endpoint config, public IP enabled | L2 | Y | `oke.py` |
| Object storage `public_access_type` | L3 | Y | `storage.py` |
| **API Gateway route `authentication` / request policies** | L3 | **N** | |
| OKE Kubernetes version, DB versions | L4 | Y | `oke.py`, `database.py` |
| Instance image / OS | L4 | Y | `compute.py` |
| **Dynamic groups (instance principals)** | L5 | **N** | without them, compute has no IAM blast radius in OCI |

## 6. L5 blast radius

Graph-native, stays in cartography:

1. Identity: compute -> attached role / managed identity / service account / dynamic group ->
   effective permissions (existing IAM relationships; OCI dynamic groups missing).
2. Network: reuse the L2 walker with internal sources (same VPC, peered VPC, TGW, DRG, VPN) to emit
   `CAN_REACH {ports}` edges from compute to data stores. Answers "if this instance falls, which
   databases can it talk to".
3. Data: data stores carry classification from the tags work (`docs/tags-processing/`).

## 7. Phases

Each phase ships independently and leaves `exposed_internet` untouched until phase 6.

| Phase | Scope | Exit criteria |
|---|---|---|
| 0 | Confirm this audit (every "verify" and "N"), agree property names and the L4 contract with cloudanix-web | signed-off schema, open questions closed |
| 1 | Ingest L2 gaps: AWS NACLs, VPC endpoints, ALB rules; GCP routes + firewall policies; Azure App Gateway + Azure Firewall | unit tests per transform, integration tests per loader |
| 2 | L2 walker per cloud writing `internet_reachable*` on attachments and LB frontends, copied to resources | integration fixtures for each scenario in section 8; diff report vs current `exposed_internet` on a real tenant |
| 3 | L3 auth signals: API GW (AWS, OCI) method auth, ALB auth actions, Easy Auth, IAP, Cloud Run / Functions invoker, Azure local-auth flags, ElastiCache AUTH | `access_auth` populated for every resource type in section 5 |
| 4 | L4 facts: `software_identity` for managed services (high confidence) first, VM image heuristics last; ECS port mappings; ElastiCache / AKS / EMR versions | contract test with cloudanix-web on sample identities |
| 5 | L5: internal `CAN_REACH` edges, OCI dynamic groups | edges present on fixture graph |
| 6 | Redefine `exposed_internet` as L1 AND L2, deprecate per-resource heuristics | console diff reviewed; customer-facing change note |

cloudanix-web work (outside this repo, listed for sequencing): L4 CVE join against
`software_identity` + `internet_reachable_ports`, KEV / EPSS / EOL feeds, combined score.

## 8. Test scenarios (fixture matrix for the walker)

Each must have an integration test per cloud where the construct exists.

| # | Setup | Expected |
|---|---|---|
| 1 | public IP, SG / NSG / firewall admits only RFC1918 | public, not reachable |
| 2 | public IP, open SG, subnet route table without internet route | public, not reachable |
| 3 | `PubliclyAccessible` DB in private subnet | public, not reachable |
| 4 | private instance behind internet LB on 443 | not public, reachable on 443 only |
| 5 | open SG, NACL / stateless rule denies | not reachable |
| 6 | NACL allows inbound but blocks ephemeral return ports | not reachable |
| 7 | SG opens 0-65535, LB listener only 443 | reachable 443 via LB; direct reachability depends on public IP |
| 8 | GCP hierarchical policy deny overrides VPC allow | not reachable |
| 9 | Azure UDR sends 0.0.0.0/0 to an NVA | reachable = unknown (blind spot), not true |
| 10 | Lambda URL `AuthType=NONE` vs `AWS_IAM` | both reachable; `access_auth` none vs required |
| 11 | S3 `Principal:*` with `aws:SourceVpce` condition | not public |
| 12 | IPv6: `::/0` SG rule, egress-only IGW only | not reachable inbound |

## 9. Open questions

1. **Identity vocabulary for L4.** What does cloudanix-web's CVE matcher key on: CPE, purl, or its
   own product names? Cartography must emit exactly that. Needs a look at cloudanix-web.
2. **Transport to cloudanix-web.** Does web read these properties from neo4j directly or from the
   OLAP ELT? New properties must be added to that pipeline.
3. **Where the combined score lives.** Proposed: web, because it needs L4. Confirm the console does
   not already compute a competing exposure score.
4. **API cost.** Some calls are per-resource (ALB `describe_rules` per listener, API GW `get_method`
   per method). Measure sync time on the largest tenant before enabling by default.
5. **Unknown handling.** Blind spots (NVA, host firewall, self-hosted auth) surface as `unknown`, not
   `false`. Confirm the console can show a third state.
6. **Passive outside-in data** (Shodan, Censys, certificate transparency) could close the
   "opened vs listening" gap without touching customers, but sends customer IPs to a third party.
   Needs a DPA review; not planned here.

## 10. Implementation

### 10.1 Layout

```
cartography/intel/exposure/          cloud-agnostic core (no cloud imports)
    ports.py      PortSet: per-protocol interval algebra (tcp/udp only), "tcp:443-443" strings
    rules.py      allow_only_open (SG, OCI lists), first_match_open (NACL, NSG, GCP firewall),
                  with_stateless_return (NACL / OCI stateless reply ports), is_world
    layers.py     property names, auth states, Reach accumulator, UNWIND writers
    software.py   identity("postgres", "15.4") -> "postgres@15.4", os_from_image_name()
cartography/intel/<cloud>/exposure_layers/
    __init__.py   run(session, common_job_parameters): reads graph, computes, writes; no API calls
    network.py    facts (subnets/routes/filters) + pure path evaluation       L1/L2
    reach.py      per-resource attachments -> Reach                            L1/L2
    access.py     per-label auth verdict functions                             L3
    software.py   per-label identity extraction                                L4
    blast_radius.py  CAN_NETWORK_REACH edges + stale cleanup                   L5
```

Each cloud's `run()` is called at the end of that cloud's account / subscription / project sync,
after the legacy exposure jobs, inside try/except: a bug here logs a warning and never fails a sync.

```
 sync (API -> graph) --> legacy *_asset_exposure jobs --> exposure_layers.run()
                                                            |  read facts (Cypher, scoped to workspace)
                                                            |  evaluate (pure Python, unit tested)
                                                            v
                                         SET public_reasons, internet_reachable*, access_auth*,
                                             software_identity*;  MERGE CAN_NETWORK_REACH
```

Every node of a covered label in the account is rewritten each run (false / [] when nothing
holds), so values never go stale. `exposed_internet*` and `publicContext` are untouched.

### 10.2 AWS (done)

| Layer | Labels |
|---|---|
| L1/L2 | NetworkInterface, EC2Instance, LoadBalancerV2, LoadBalancer, RDSInstance, RDSCluster, RedshiftCluster, EMRCluster, ElasticacheCluster, APIGatewayRestAPI, AWSLambda, EKSCluster, AWSCloudfrontDistribution, ESDomain, S3Bucket, SQSQueue, AWSSNSTopic |
| L3 | the above plus EBSSnapshot, RDSSnapshot, RDSClusterSnapshot, EC2Image |
| L4 | RDSInstance, RDSCluster, ElasticacheCluster, EKSCluster, ESDomain, AWSLambda (`managed_config`); EC2Instance (`image_name`) |
| L5 | EC2Instance -[:CAN_NETWORK_REACH]-> RDSInstance / RedshiftCluster / ElasticacheCluster |

`internet_reachable_via` values: `direct_ipv4`, `direct_ipv6`, `elbv2:<arn>`, `member:<rds arn>`,
`function_url`, `apigateway_endpoint`, `apigateway_trigger`, `alb_trigger`, `cloudfront_trigger`,
`cloudfront`, `public_endpoint`, `aws_service_endpoint`.

Rollout:
- New sync key `ec2:network_acl`; the backend's requested-sync list must include it. Without NACL
  data a subnet is treated as the AWS default NACL (allow all), so results stay as permissive as before.
- New permission: `ec2:DescribeNetworkAcls` (in ReadOnlyAccess and SecurityAudit).
- `get_resources(embed=methods)` and `describe_cache_clusters(ShowCacheNodeInfo=True)` add data
  to existing calls, no new requests.

Known ceilings (each marked `ponytail:` in code): multi-ENI instances are unioned; LB target
admission accepts any source, not only the LB; ALB auth actions, Redis RBAC, classic-ELB targets,
peered-VPC and TGW reach are not evaluated; Redshift / EMR subnets are not ingested, so route and
NACL checks are skipped for them (SG verdict kept).

### 10.3 cloudanix-web contract

Read per node: `internet_reachable`, `internet_reachable_ports`, `access_auth`,
`software_identity`, `software_identity_source`; per edge: `CAN_NETWORK_REACH.ports`. L4 join:
`software_identity` -> CVEs (product/version vocabulary is open question 1), keep CVSS `AV:N`,
keep CVEs whose service port is in `internet_reachable_ports`, weight by KEV / EPSS, then by
`access_auth = none` and by data stores reachable through `CAN_NETWORK_REACH` + IAM edges.
