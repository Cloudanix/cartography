# Console link audit (2026-10-18)

Every node cartography writes should carry a `consolelink` built by `cloudconsolelink`.
This audit compared each node label against what the library can build.

Phase 1: fill library gaps in `cloud-console-links` (branch `console-link-gaps`).
Phase 2 (this repo, after the library release): bump `cloudconsolelink` and wire the items below.

Note: cartography pins `cloudconsolelink~=4.0.1` (means `<4.1`), so even 4.1.x is not picked up today.
Bump the pin in `setup.py` and every `*.requirements.txt`.

## Crashes / data loss caused by link calls (fix first)

| where | problem | fix |
|---|---|---|
| gcp/dns.py:118 | `dns_resource_record_set` without `dns_type` raises; record sets, DNS keys and cleanup never run | pass `dns_type=rs['type']` |
| gcp/containerregistry.py:68 | `location=`/`repository_name=` not accepted (TypeError); whole artifacts sync fails. Also writes `console_link` | `region=`, `instance_name=`; write `consolelink` |
| gcp/containerregistry.py:135/156 | `container_registry` unregistered (ValueError, swallowed, GCR repos dropped) | use library's new name / `artifact_registry_home` |
| gcp/pubsub.py:52 | `subscription_name=` (TypeError once the empty-list bug below is fixed) | `subscription_id=` |
| aws/securityhub.py:72, aws/emr.py:65 | `''` ARN raises `ARNTooShortError` | guard empty ARN |
| aws/eks.py:92 | `None` ARN -> AttributeError | guard |
| azure (most modules) | missing `primary_ad_domain_name` raises ValueError; only key_vaults/containerregistry catch it | guard once at module entry |

## Bugs that silently drop or wipe links

- aws `models/aws/ec2/subnet_instance.py:20` declares `consolelink` but instance-derived subnet rows lack it, so `ec2:instance` sync nulls `EC2Subnet.consolelink`. Same for `reservations.py`, `keypairs.py` models. Drop the property from those models.
- azure: `iam.py:492` AzureGroup MERGE never writes link; `aks.py:659` typo `a.conolelink`; `containerregistry.py:194` writes `console_link`; `network.py:460` bastion never writes link; `sql.py:1684` `tae.consolelink = tae.consolelink`.
- azure: 32 writes are only in `ON CREATE SET`, so fixes never reach existing nodes (aks.py all loaders; compute.py 174/377/848/926; containerregistry.py 194; function_app.py 151; iam.py 336/890/1034/1176/1317; key_vaults.py all; monitor.py 77; network.py 707/807/939/1140/1247/1300; securitycenter.py 66; tag.py 69). Move to `SET`.
- gcp transforms that reset input to `[]` before looping (nodes never written): apigateway.transform_locations, cloudmonitoring.transform_metric_descriptors, cloudrun.transform_configurations/mappings/revisions/services, pubsub.transform_subscriptions/topics.
- gcp/pubsublite.py:56/140 `project_id = project_id,` stores a tuple.
- gitlab/projects.py: GitLabProject MERGEd on `path` then `SET id = numeric`, so a new node every run.

## Wrong arguments (link built but broken)

- aws: lambda alias/event-source-mapping/layer fake ARNs without region (`lambda_function.py:303-322`); DynamoDB GSI ARN without region (`dynamodb.py:56`); Route53 zone doubles `/hostedzone/` (`route53.py:505`); EventBridge rule uses fake `cloudwatch:rule` ARN (`cloudwatch.py:124`, use real `events` ARN); flow log ARN typo `vcp-flow-log` (`cloudwatch.py:494`); `cloudwatch.py:218` discards `.replace()` result; inline policies get a fake managed-policy ARN; IAM users with path.
- gcp: NIC `network_name` is a self-link (`compute.py:576/582`, split last segment); regional instance group passes name as region (`loadbalancer.py:291`); API Gateway passes displayName as id (`apigateway.py:112`); Firestore database passed as collection; metric descriptor linked to logs-metrics page.
- azure: service principal uses overwritten custom id (`iam.py:1004`, pass object_id); domain passes `tenants/.../domains/x` (`iam.py:1150`, pass name); subscription passes bare GUID (`subscription.py:44,76`, pass `sub.id`); VM extension passes VM id (`compute.py:359`).

## Library supports it, cartography does not set it

- aws: AWSSNSTopic (`sns.py:84` hardcodes `''`), AWSSNSTopicSubscription, ECSCluster/Service/Task/ContainerInstance, ElasticacheTopic, managed AWSPolicy, classic ELB `LoadBalancer` node (computed at `load_balancers.py:137`, only written to listeners), ELBV2Listener, KMSAlias, RDSReservedDBInstance, DBSubnetGroup, AWSESReservedInstance, APIGatewayResource, APIGatewayClientCertificate, AWSOrganization, Identity Center user/group/permission set, AWSCloudWatchFlowLog.
- gcp: GCPCloudTasksQueue, GCPSpannerInstance, GCPSpannerInstanceDatabase, GCPUrlMap (`url_map`), GCPProxy https (`target_https_proxy`), GCPDNSKey (`dns_zone`), plus new library methods: GKENodePool, GCPDataFlowJob, GCPImage, GCPProject/Organization/Folder, BigQuery dataset/table, GCPSQLDatabase, GCPSpannerInstanceBackup, ssl proxy, global forwarding rules.
- azure: AzureTenant, AzureExternalPrincipal, AzureContainerRepository/Image, LB frontend/backend pools, NIC IP configs, SQL private endpoints/firewall rules, AzureRole (scope IAM blade).
- oci: nothing wired. Every OCI node needs `OCILinker()` (node `region` is already the full name; IAM nodes need tenancy home region; buckets pass `namespace` + `name`).
- github/gitlab/bitbucket/azuredevops: nothing wired. Use the new `GitLinker` (library) for every label; where the API already returns a web URL (GitHub org/repo/team `url`, GitLab `web_url`, Bitbucket repo `console_link`, ADO repo `weburl`) either works. Branches need the parent repo path stored on the branch at transform time.

## Out of scope

Kubernetes and DigitalOcean syncs are disabled in `cartography/sync.py`; k8s nodes lack cloud/account/region so no console link is buildable.
