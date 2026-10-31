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
| Load balancer frontends, backend pools | L2 | Y | `network.py`, `compute.py` |
| LB rules, inbound NAT rules, NAT pools (ports) | L2 | **Y (new)** | `AzureLoadBalancerRule`, from the same `list_all` response |
| Public IP and LB SKU | L2 | **Y (new)** | Standard SKU is closed without an NSG, Basic is open |
| VMSS subnet / NSG ids | L2 | **Y (new)** | `compute.py`; per-instance public IP SKU still N (counted as Basic) |
| LB backend pools by IP address | L2 | N | |
| **Application Gateway** (listeners, backend pools, WAF) | L2/L3 | **N** | |
| **Azure Firewall** (DNAT rules) | L2 | **N** | |
| Effective NSG / effective routes | L2 | N | optional shortcut; per-NIC API calls are expensive, compute it ourselves instead |
| Private endpoints | L2 | Y | `network.py`, `sql.py`, `cosmosdb.py` |
| `public_network_access` / network rule sets | L2/L3 | Y | storage, cosmosdb, ACR, function app, AKS |
| SQL / Cosmos firewall rules, function app IP restrictions | L2 | Y | `sql.py`, `cosmosdb.py`, `function_app.py` |
| AKS `api_server_access_profile` (authorized IPs, private) | L2 | Y | `aks.py` |
| Storage `allow_blob_public_access` + container access level | L3 | Y | `storage.py` |
| **App Service / Function auth settings (Easy Auth)** | L3 | **N** | |
| SQL Entra ID only auth, Cosmos `disable_local_auth` | L3 | **Y (new)** | `sql.py`, `cosmosdb.py`; Service Bus etc. still N |
| ACR network rule default action, anonymous pull | L2/L3 | **Y (new)** | `containerregistry.py` |
| AKS Kubernetes version | L4 | **Y (new)** | `aks.py` |
| VM image reference (publisher / offer / sku / version) | L4 | Y | `compute.py` |
| PostgreSQL / MySQL server version, App Service runtime stack | L4 | Y | Azure SQL always reports "12.0": no identity emitted |
| Minimum TLS version (storage, SQL, app service) | L4 | N | |
| Managed identities on VMs / apps | L5 | Y | `compute.py`, `iam.py` |

### 5.3 GCP

| Need | Layer | State | Where / note |
|---|---|---|---|
| VPC firewall rules | L2 | Y | `compute.py` |
| Firewall source tags / source SAs / targets / per-rule allowed+denied ports | L2/L5 | **Y (new)** | flat properties on the firewall node; tag- and SA-sourced rules were invisible before |
| **Hierarchical / network firewall policies** | L2 | **N** | evaluated before VPC rules: some `internet_reachable = true` may really be false |
| VPC routes (default internet gateway route) | L2 | **Y (new)** | `GCPRoute`, one `compute.routes().list` per project, needs `compute.routes.list` |
| Instance external IPs (`accessConfigs`) | L1/L2 | Y | `compute.py` |
| Forwarding rules, backend services, URL maps, target proxies | L2 | Y | `compute.py`, `loadbalancer.py`, `cloudcdn.py` |
| Backend service `port_name` / protocol, instance group `named_ports` | L2 | **Y (new)** | same calls |
| Unmanaged instance group members | L2 | N | only managed-group backends resolve |
| **Cloud Armor security policies** | L4 (mitigation) | **N** | |
| IAP on backend services | L3 | **Y (new)** | `iap_enabled` |
| Functions ingress | L2 | Y | `cloudfunction.py` |
| Cloud Run services, ingress, invokers | L2/L3 | **pending PR #507** | on `main` Cloud Run services are never loaded (`transform_services` empties its input); #507 fixes it and writes `ingress`, `invoker_iam_disabled`, `iam_policy_status`, `public_invokers`, which the layers already read |
| Functions `allUsers` invoker | L3 | Y | existing bindings |
| GCS `allUsers`, public access prevention | L3 | Y | `storage.py` |
| GKE master authorized networks, private cluster | L2 | Y | `gke.py` |
| GKE master version | L4 | Y | `gke.py` |
| Cloud SQL `databaseVersion`, `authorizedNetworks`, `ipv4Enabled` | L2/L4 | Y | `sql.py` |
| Cloud Functions runtime | L4 | Y | `cloudfunction.py` |
| Instance source image / licenses (OS heuristic) | L4 | Y | `compute.py`, `images.py` |
| Instance service accounts + scopes | L5 | Y | `compute.py`, `iam.py` |

### 5.4 OCI

| Need | Layer | State | Where / note |
|---|---|---|---|
| Security lists (ingress rules, stateless flag) | L2 | Y | `network.py` |
| NSGs + rules | L2 | Y | `network.py`, used by LB, DB, OKE, API GW |
| Route tables, internet gateway, NAT gateway | L2 | Y | `network.py`; used by `oci_subnet_asset_exposure` |
| **Service gateway, DRG, local peering** | L2 | **N** | needed for internal / on-prem sources (L5), not for internet |
| VNIC public IP, `prohibit_public_ip_on_vnic` | L1/L2 | Y | `network.py`, `compute.py` |
| LB listeners, backend sets | L2 | Y | `load_balancer.py`; backend ports **Y (new)** as `backend_endpoints` from the same list call |
| VNIC IPv6 addresses | L1/L2 | N | reason the OCI walker is IPv4 only |
| **WAF policies, Network Firewall** | L2/L4 | **N** | |
| ADB whitelisted IPs, private endpoint | L2 | Y | `database.py` |
| OKE endpoint config, public IP enabled | L2 | Y | `oke.py` |
| Object storage `public_access_type` | L3 | Y | `storage.py` |
| API Gateway route `authentication` / request policies | L3 | **Y (new)** | `api_gateway.py`: ListDeployments + GetDeployment per active deployment; policy verb `read api-deployments` |
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

Answered for questions 1, 2, 3 and 5 in `docs/console-exploitability-changes.md` section 2: no
product matcher exists (scanners report CVE ids; managed services need a new CPE map), transport is
ELT through the inventory-sync-aws field allowlist (edge properties dropped today), the console
scores on `d_assets.public_facing`, and storage is two-state. Remaining decisions: that doc,
section 4.

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

ALB authentication (L3): the ELBv2 sync calls `describe_rules` per HTTP(S) listener of an
application LB and stores `all_paths_authenticated` / `auth_action_types` on `ELBV2Listener`. A path
is authenticated when its first action (by `Order`) is `authenticate-oidc`, `authenticate-cognito`
or `jwt-validation`; `redirect` / `fixed-response` paths never reach a target and do not count. An
LB whose every listener is fully authenticated gets `access_auth=required` (`alb_authenticate_*`),
and so does an EC2Instance whose only `internet_reachable_via` entries are such LBs. A failed
`describe_rules` leaves the facts null (unknown, never authenticated).

Cross-VPC reach (L5): `CAN_NETWORK_REACH` crosses VPCs via an active peering (`peering:<pcx>`) or a
TGW with available attachments in both VPCs (`tgw:<id>`), when the instance subnet routes the store's
subnet (or VPC) CIDR to that gateway and the store side routes the instance IP back. The store SG
must admit the instance by CIDR, or by SG reference across same-region peering only. `EC2Route` now
carries `vpc_peering_connection_id` / `transit_gateway_id` (same `describe_route_tables` call).

Rollout (follow-up): one new call, `elasticloadbalancing:DescribeRules` (under
`elasticloadbalancing:Describe*`). Cross-VPC edges need sync keys `ec2:vpc_peering`, `ec2:tgw`,
`ec2:route_table` (already in the customer list) and appear after the next route table sync.

Known ceilings (each marked `ponytail:` in code): multi-ENI instances are unioned; LB target
admission accepts any source, not only the LB; LB auth requires every listener to authenticate,
even unreachable ones; Redis RBAC and classic-ELB targets are not evaluated; Redshift / EMR subnets
are not ingested, so route and NACL checks are skipped for them (SG verdict kept). L5: IPv4 only;
NACLs between subnets and longest-prefix route match not evaluated; TGW route tables not ingested
(default association / propagation assumed); TGW SG referencing not modeled; both ends in the same
account; stores without ingested subnets use their whole VPC's routes and CIDRs (upper bound).

### 10.3 OCI (done)

Runs per compartment after `OCI_ANALYSIS_JOBS`. Writes compartment resources; reads network
objects (subnets, security lists, NSGs, gateways, LBs) tenancy-wide, since a VNIC or LB can sit in
another compartment's network.

| Layer | Labels |
|---|---|
| L1/L2 | OCIVnic, OCIInstance, OCIDbNode, OCIDbSystem, OCILoadBalancer, OCINetworkLoadBalancer, OCIOKECluster (6443), OCIApiGateway (443), OCIAutonomousDatabase (1521-1522, 443), OCIStorageBucket, OCIContainerRepository (service endpoint 443) |
| L3 | buckets `ObjectRead*` / public repos / anonymous gateway deployment = none; ADB (credentials, mTLS wallet), DB systems, OKE = required; instances, LBs, gateways without readable deployments = unknown |
| L4 | `kubernetes@` (OKE clusters, node pools), `oracle-database@` (ADB, DB system, DB home), instance OS (`image_name`) |
| L5 | OCIInstance -[:CAN_NETWORK_REACH]-> OCIDbSystem, private-endpoint OCIAutonomousDatabase (same VCN) |

Path: public IP, subnet allows public IPs, `0.0.0.0/0` route to an enabled IGW, then security lists
of the subnet UNION NSGs of the attachment (OCI admits a packet when any of them allows it).
Stateless ingress needs an egress rule covering ephemeral reply ports.

Rollout: policy verb `read api-deployments` (or `inspect` + `read`) in the tenancy policy. If
denied, gateway auth stays `unknown`, never "no deployments".

IPv6 (VNICs): a VNIC with a global IPv6 address (`OCIVnic.ipv6_addresses`, from the GetVnic response
already fetched, no new call or policy verb) is evaluated per family: `::/0` route to an enabled
IGW, `::/0` security list / NSG rule on the port, stateless rules needing `::/0` return egress.
Families never mix. `prohibit_public_ip_on_vnic` (set from `prohibitInternetIngress`) blocks IPv6
too. Reported as `public_ipv6` / via `direct_ipv6`.

Ceilings: LB, NLB, OKE and API Gateway endpoints IPv4 only (their IPv6 addresses not ingested); a
global-looking prefix declared private (`Vcn.ipv6_private_cidr_blocks`) counts as global; unresolved
route table does not block (via `route_table_unresolved`);
LB -> backend hop accepts any source and skips its stateless return check; API Gateway multi-auth
treated as authenticated; L5 same VCN only; dynamic groups, WAF, Network Firewall not ingested.

### 10.4 GCP (done)

Runs in `start_gcp_ingestion` after `gcp_storage_bucket_policy_analysis.json`, per project.

| Layer | Labels |
|---|---|
| L1/L2 | GCPInstance (external IPv4 / IPv6, default route to `default-internet-gateway`, firewall), instances behind external LBs, GCPForwardingRule, GCPBackendService, GKECluster, GCPSQLInstance, GCPFunction, GCPCloudRunService, GCPBucket, GCPBigqueryDataset |
| L3 | `allUsers` / `allAuthenticatedUsers` on buckets, datasets, invokers = none; IAP backends, Cloud SQL, GKE = required; instances, forwarding rules, unread Cloud Run policy = unknown |
| L4 | GKE master, Cloud SQL `databaseVersion` (`mysql@8.0`), Functions runtime (`python@3.12`), instance OS from boot image / license name (`image_name`) |
| L5 | GCPInstance -[:CAN_NETWORK_REACH]-> GCPSQLInstance (private IP, same VPC) and -> GCPInstance (firewall source tag / SA) |

Firewall: first match by priority, deny wins a tie, implied deny last; targets match by tag or SA.
Proxy LBs need the Google front-end ranges (130.211.0.0/22, 35.191.0.0/16) admitted on the backend's
named port; passthrough LBs and target pools need world rules.

Rollout: `compute.routes.list` (in `roles/viewer`, `roles/compute.viewer`,
`roles/compute.networkViewer`; verified in Google's role reference). Until routes are ingested a missing route does
not block. Instances whose network firewalls are not visible (Shared VPC host outside the
workspace) are marked reachable on every port with via `direct_ipv4_unresolved_firewall`, matching
the legacy job's fail-safe.

Firewall policies: hierarchical (org, then folders) and global network firewall policies are ingested
per VPC with one `networks.getEffectiveFirewalls` call per network (`GCPVpc -[:RESOURCE]->
GCPFirewallPolicyRule`; `GCPVpc.network_firewall_policy_enforcement_order` from `networks.list`). L2
and L5 follow Cloud NGFW order: org policy, folder policies, then VPC rules and the network policy in
the network's enforcement order (default AFTER_CLASSIC_FIREWALL), then implied deny; allow / deny end
evaluation, `goto_next` or no match falls to the next level (core `rules.tiered_open`). GFE /
health-check traffic is non-internet context. Policies only narrow L5 edges, never add them.
Rollout: `compute.networks.getEffectiveFirewalls` (in `roles/viewer`, `roles/compute.viewer`,
`roles/compute.networkViewer`; not in `roles/iam.securityReviewer`). A refused or failed call leaves
the network on VPC rules only, never "unreachable". Not yet tested with a project-only credential
against a real org (docs imply inherited policies are returned).

Ceilings: regional network firewall policies (need a per-region, per-network call); secure tag
bindings not ingested (tag-targeted allow / goto_next applies, deny does not); domain, geolocation,
threat-list and address-group sources never count as the whole internet; `apply_security_profile_group`
counted as allow; hierarchy order taken from response order; only `/0` routes compared;
unmanaged instance group members; regional external Application LBs (proxy-only subnet source) read
as unreachable; multi-NIC unioned; L5 skips CIDR-sourced internal rules (`default-allow-internal`
would link every pair).

### 10.5 Azure (done)

Runs in `_sync_multiple_subscriptions` after the `azure_*_asset_exposure` jobs, per subscription.

| Layer | Labels |
|---|---|
| L1/L2 | AzureNetworkInterface, AzureVirtualMachine, AzureVirtualMachineScaleSet, AzureNetworkLoadBalancer, AzureStorageAccount, AzureStorageBlobContainer, AzureSQLServer, AzureSQLDatabase, AzureCosmosDBAccount, AzureKeyVault, AzureFunctionApp, AzureCluster (AKS), AzureContainerRegistry |
| L3 | anonymous blob container, ACR anonymous pull = none; storage, SQL (`entra_id_only` / credentials), Cosmos, Key Vault, AKS = required; Function App with Easy Auth rejecting anonymous = required; other Function Apps, VM, VMSS, NIC, LB, App Gateway = unknown |
| L4 | VM image offer / sku (`image_name`), AKS `kubernetes@`, PostgreSQL / MySQL, App Service runtime stack |
| L5 | AzureVirtualMachine -[:CAN_NETWORK_REACH]-> AzureSQLServer / AzureCosmosDBAccount (via `firewall_ip_rule`, `azure_services_rule`, `public_endpoint`) |

Path: public IP, or public LB frontend + LB rule / NAT rule / NAT pool, then subnet NSG AND NIC NSG
on the backend port; first match by priority, no match = deny. Standard SKU IP / LB with no NSG at
either level admits nothing. A UDR `0.0.0.0/0` to anything but Internet is reported as
`unknown:udr_default_route_<hop>` in `internet_reachable_via` and not marked reachable. PaaS
firewall semantics follow the legacy exposure jobs (SQL rule wider than /8 = world).

Rollout: no new API calls or permissions. LB rules and SKUs appear after the next network sync;
until then VMs behind an LB get no LB path and every SKU counts as Basic (open).

App Gateway, Azure Firewall DNAT, Easy Auth (follow-up): `network_gateways.py` (called from
`network.sync`) ingests `AzureApplicationGateway` (SKU, WAF enabled / mode / policy) -[:HAS]->
`AzureApplicationGatewayRule` (one per routing target: listener protocol / port, public frontend,
backend settings port, backend NIC ipconfigs / IPs / FQDNs), and `AzureFirewall` -[:HAS]->
`AzureFirewallNatRule` (classic Dnat collections plus the attached policy's NAT collections), linked
to subnet and public IPs; backend NICs `CONNECTED_TO` the gateway. `exposure_layers/gateways.py`: a
public-frontend gateway is reachable on its listener ports through its subnet NSG (via
`public_listener`), backends get the backend settings port via `appgw:<id>`. A world-sourced DNAT
rule to the firewall's public IP opens the translated port on the NIC holding the translated private
IP via `azure_firewall_dnat:<id>`. Because the gateway proxies and the firewall SNATs, backend NSGs
are evaluated with the front door's subnet as source plus implied AllowVnetInBound (`Internet` tag
does not match). A private IP repeated across VNets resolves to the NIC in the front door's VNet or
stays unresolved. WAF Prevention is an L3 reason (`waf_prevention`), not a block. Function Apps are
`required` (`easy_auth`) when auth is on and the unauthenticated action rejects (RedirectToLoginPage,
Return401, Return403); AllowAnonymous, `requireAuthentication` off, excluded paths or unreadable
settings stay `unknown`. Subnets gain `address_prefixes`, VMSS `appgw_backend_pool_ids`; NIC ipconfig
`private_ip_address` is refreshed every sync (was create-only).

Rollout (follow-up), read-only and covered by Reader: `application_gateways.list_all` and
`azure_firewalls.list_all` (once per subscription), `firewall_policy_rule_collection_groups.list`
(per policy in use), `web_apps.get_auth_settings_v2_without_secrets` (per site; GET
`config/authsettingsV2`, `Microsoft.Web/sites/config/Read`; the `/list` variant needs
`config/list/Action`, returns secrets, and is never called). Until the next network sync no
front-door paths appear.

Ceilings: NSG rules aimed at a single destination address are not matched per NIC (upper bound);
`::/0` treated as IPv4 world; WAF policy mode, v2 TCP/TLS listeners, FQDN backends, IP-group DNAT
sources, DNAT to an internal LB, cross-subscription or parent firewall policies, Virtual WAN hub
firewalls not handled; VNet peerings not ingested; one excluded Easy Auth path makes the site
`unknown`; UDR `0.0.0.0/0` to an Azure Firewall stays `unknown:udr_default_route_virtualappliance`;
VM power state ignored; L5 does not resolve SNAT / NAT gateway egress IPs, private
endpoints or service endpoints.

### 10.6 Validation

- 90 exposure-layer tests (core, 4 clouds, unit + integration) pass together in one Neo4j, stable
  over repeated runs.
- Full AWS / Azure / GCP / OCI unit + integration suites plus job-file tests: identical failure set
  to base `2e76d1a09` (124 failed, 22 errors, all pre-existing); branch adds 78 passing tests.
- pre-commit (flake8, autopep8, trailing commas, import order, mypy) clean on new code; remaining
  findings are on untouched lines of existing files.

### 10.7 cloudanix-web contract

Read per node: `internet_reachable`, `internet_reachable_ports`, `access_auth`,
`software_identity`, `software_identity_source`; per edge: `CAN_NETWORK_REACH.ports`. L4 join:
`software_identity` -> CVEs (product/version vocabulary is open question 1), keep CVSS `AV:N`,
keep CVEs whose service port is in `internet_reachable_ports`, weight by KEV / EPSS, then by
`access_auth = none` and by data stores reachable through `CAN_NETWORK_REACH` + IAM edges.
