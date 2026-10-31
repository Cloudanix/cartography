from unittest.mock import MagicMock

import cartography.intel.gcp.cloudcdn
import cartography.intel.gcp.compute
import cartography.intel.gcp.instance_groups
import cartography.intel.gcp.loadbalancer
from cartography.util import run_analysis_job
from cartography.util import run_cleanup_job

PROJECT = 'proj-lb'
OTHER_PROJECT = 'proj-lb-other'
TAG = 500
PARAMS = {
    'UPDATE_TAG': TAG, 'WORKSPACE_ID': 'ws-lb', 'GCP_ORGANIZATION_ID': 'org-lb', 'GCP_PROJECT_ID': PROJECT,
    'LIMIT_SIZE': 1000,
}
API = 'https://www.googleapis.com/compute/v1'
ZONE = f'projects/{PROJECT}/zones/us-east1-b'


def _seed_projects(neo4j_session):
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(o:GCPOrganization{id: $org})
        MERGE (o)-[:OWNER]->(:GCPProject{id: $project})
        MERGE (o)-[:OWNER]->(:GCPProject{id: $other})
        """,
        ws=PARAMS['WORKSPACE_ID'], org=PARAMS['GCP_ORGANIZATION_ID'], project=PROJECT, other=OTHER_PROJECT,
    )


def _load_forwarding_rules(neo4j_session):
    """Forwarding rules through the real transform, target resolution and loader."""
    def fwd(name, scheme, region=None, **refs):
        location = f'regions/{region}' if region else 'global'
        item = {
            'name': name, 'loadBalancingScheme': scheme,
            'selfLink': f'{API}/projects/{PROJECT}/{location}/forwardingRules/{name}',
        }
        if region:
            item['region'] = f'{API}/projects/{PROJECT}/regions/{region}'
        item.update({k: f'{API}/projects/{PROJECT}/{v}' for k, v in refs.items()})
        return item

    response = {
        'id': f'projects/{PROJECT}/global/forwardingRules', 'items': [
            fwd('https-fr', 'EXTERNAL_MANAGED', target='global/targetHttpsProxies/web-https'),
            fwd('pool-fr', 'EXTERNAL', region='us-east1', target='regions/us-east1/targetPools/pool'),
            fwd(
                'internal-fr', 'INTERNAL', region='us-east1',
                backendService='regions/us-east1/backendServices/internal',
            ),
        ],
    }
    client = MagicMock()
    client.targetHttpsProxies.return_value.get.return_value.execute.return_value = {
        'urlMap': f'{API}/projects/{PROJECT}/global/urlMaps/web',
        'sslPolicy': f'{API}/projects/{PROJECT}/global/sslPolicies/modern',
    }
    client.targetPools.return_value.get.return_value.execute.return_value = {
        'instances': [f'{API}/{ZONE}/instances/vm-pool'],
    }
    rules = cartography.intel.gcp.compute.transform_gcp_forwarding_rules(response)
    cartography.intel.gcp.compute.resolve_external_lb_backends(client, rules)
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(neo4j_session, rules, TAG)


def _load_lb_resources(neo4j_session):
    cartography.intel.gcp.compute.load_proxies(
        neo4j_session, [{
            'id': f'projects/{PROJECT}/global/targetHttpsProxies/web-https', 'name': 'web-https', 'type': 'https',
            'sslPolicy': f'{API}/projects/{PROJECT}/global/sslPolicies/modern',
        }], PROJECT, TAG,
    )
    cartography.intel.gcp.loadbalancer.load_ssl_policies(
        neo4j_session, [
            {'id': f'projects/{PROJECT}/global/sslPolicies/modern', 'name': 'modern'},
            {'id': f'projects/{PROJECT}/global/sslPolicies/unused', 'name': 'unused'},
        ], PROJECT, TAG,
    )
    cartography.intel.gcp.loadbalancer.load_url_maps(
        neo4j_session, [{
            'id': f'projects/{PROJECT}/global/urlmaps/web', 'name': 'web',
            'selfLink': f'{API}/projects/{PROJECT}/global/urlMaps/web',
            'defaultService': f'{API}/projects/{PROJECT}/global/backendServices/web',
            'pathMatchers': [{
                'defaultService': f'{API}/projects/{PROJECT}/global/backendBuckets/static',
                # A backend service in another project (cross-project reference) is not resolved.
                'pathRules': [{'service': f'{API}/projects/{OTHER_PROJECT}/global/backendServices/shared'}],
            }],
        }], PROJECT, TAG,
    )
    cartography.intel.gcp.cloudcdn.load_backend_buckets(
        neo4j_session, [{
            'id': f'projects/{PROJECT}/global/backendBuckets/static-assets-gcs', 'bucketName': 'static-assets-gcs',
            'name': 'static', 'selfLink': f'{API}/projects/{PROJECT}/global/backendBuckets/static',
        }], PROJECT, TAG,
    )

    def service(project, name, groups, region='global'):
        location = 'global' if region == 'global' else f'regions/{region}'
        return {
            'id': f'projects/{project}/{location}/backendServices/{name}', 'name': name,
            'backends': [{'group': f'{API}/{ZONE}/instanceGroups/{g}'} for g in groups],
        }
    cartography.intel.gcp.cloudcdn.load_backend_services(
        neo4j_session, [
            service(PROJECT, 'web', ['web-mig', 'web-unmanaged']),
            service(PROJECT, 'internal', ['internal-mig'], region='us-east1'),
            service(PROJECT, 'orphan', ['orphan-mig']),
        ], PROJECT, TAG,
    )
    cartography.intel.gcp.cloudcdn.load_backend_services(
        neo4j_session, [service(OTHER_PROJECT, 'shared', ['web-mig'])], OTHER_PROJECT, TAG,
    )
    cartography.intel.gcp.loadbalancer.load_instance_groups(
        neo4j_session, [
            {'id': f'{ZONE}/instanceGroups/web-unmanaged'},
        ], PROJECT, TAG,
    )
    ig = cartography.intel.gcp.instance_groups
    ig._load_managed_instance_groups(
        neo4j_session, [
            {
                'id': f'{API}/{ZONE}/instanceGroupManagers/{name}', 'name': name,
                'instance_group': f'{ZONE}/instanceGroups/{name}',
            }
            for name in ('web-mig', 'internal-mig', 'orphan-mig')
        ], PROJECT, TAG,
    )
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $project})
        UNWIND ['vm-mig', 'vm-pool', 'vm-internal', 'vm-orphan', 'vm-mig-stopped'] AS name
        MERGE (p)-[:RESOURCE]->(i:GCPInstance:GCPComputeInstance:Instance{id: $zone + '/instances/' + name})
        SET i.self_link = $api + '/' + i.id,
            i.status = CASE WHEN name ENDS WITH 'stopped' THEN 'TERMINATED' ELSE 'RUNNING' END
        """,
        project=PROJECT, zone=ZONE, api=API,
    )
    ig._load_vm_to_mig_part_of_relationships(
        neo4j_session, [
            {'vm_self_link': f'{API}/{ZONE}/instances/{vm}', 'mig_id': f'{API}/{ZONE}/instanceGroupManagers/{mig}'}
            for vm, mig in (
                ('vm-mig', 'web-mig'), ('vm-mig-stopped', 'web-mig'), ('vm-internal', 'internal-mig'),
                ('vm-orphan', 'orphan-mig'),
            )
        ], TAG,
    )


def _exposed(neo4j_session):
    rows = neo4j_session.run(
        """
        MATCH (:GCPProject)-[:RESOURCE]->(n) WHERE n.exposed_internet
        RETURN [l IN labels(n) WHERE l IN ['GCPForwardingRule', 'GCPProxy', 'GCPUrlMap', 'GCPSSLPolicy',
            'GCPBackendService', 'GCPBackendBucket', 'GCPInstanceGroup', 'GCPInstance']][0] AS label,
            split(n.id, '/')[-1] AS name, n.exposed_internet_type AS types
        """,
    )
    return {(r['label'], r['name']): r['types'] for r in rows}


def test_external_load_balancer_exposes_its_front_end_and_resolved_backends(neo4j_session):
    _seed_projects(neo4j_session)
    _load_forwarding_rules(neo4j_session)
    _load_lb_resources(neo4j_session)
    # Flagged by an earlier run; nothing routes to it now.
    neo4j_session.run(
        "MATCH (n:GCPBackendService{name: 'orphan'}) SET n.exposed_internet = true, "
        "n.exposed_internet_type = ['external_load_balancer']",
    )

    run_analysis_job('gcp_load_balancer_exposure.json', neo4j_session, PARAMS)
    run_analysis_job('gcp_compute_instance_analysis.json', neo4j_session, PARAMS)

    lb = ['external_load_balancer']
    assert _exposed(neo4j_session) == {
        ('GCPForwardingRule', 'https-fr'): lb,
        ('GCPForwardingRule', 'pool-fr'): lb,
        ('GCPProxy', 'web-https'): lb,
        ('GCPSSLPolicy', 'modern'): lb,
        ('GCPUrlMap', 'web'): lb,
        ('GCPBackendService', 'web'): lb,
        ('GCPBackendBucket', 'static-assets-gcs'): lb,
        ('GCPInstanceGroup', 'web-unmanaged'): lb,
        ('GCPInstanceGroup', 'web-mig'): lb,
        # No external IP needed: reachable through the load balancer.
        ('GCPInstance', 'vm-mig'): lb,
        ('GCPInstance', 'vm-pool'): lb,
    }


def test_global_forwarding_rules_hang_off_their_project_and_are_cleaned_up(neo4j_session):
    _seed_projects(neo4j_session)
    _load_forwarding_rules(neo4j_session)
    neo4j_session.run(
        "MATCH (p:GCPProject{id: $project}) MERGE (p)-[:RESOURCE]->(:GCPForwardingRule{id: 'gone-fr', lastupdated: 1})",
        project=PROJECT,
    )

    run_cleanup_job('gcp_compute_forwarding_rules_cleanup.json', neo4j_session, PARAMS)

    names = neo4j_session.run(
        "MATCH (:GCPProject{id: $project})-[:RESOURCE]->(fr:GCPForwardingRule) RETURN fr.name AS name",
        project=PROJECT,
    ).value()
    assert sorted(names) == ['https-fr', 'internal-fr', 'pool-fr']


LB = ['external_load_balancer']


def _seed_project(neo4j_session, project, workspace='ws-lb'):
    neo4j_session.run(
        """
        MERGE (:CloudanixWorkspace{id: $ws})-[:OWNER]->(o:GCPOrganization{id: $org})
        MERGE (o)-[:OWNER]->(p:GCPProject{id: $project})
        SET p.workspace_ids = [w IN coalesce(p.workspace_ids, []) WHERE w <> $ws] + $ws
        """,
        ws=workspace, org=PARAMS['GCP_ORGANIZATION_ID'], project=project,
    )


def _params(project):
    return {**PARAMS, 'GCP_PROJECT_ID': project}


def _external_rule(project, name, **refs):
    """A forwarding rule as transform + resolve_external_lb_backends leave it."""
    partial_uri = f'projects/{project}/global/forwardingRules/{name}'
    return {
        'partial_uri': partial_uri, 'name': name, 'project_id': project, 'load_balancing_scheme': 'EXTERNAL_MANAGED',
        **refs,
    }


def _backend_service(project, name, scheme, groups):
    return {
        'id': f'projects/{project}/global/backendServices/{name}', 'name': name, 'loadBalancingScheme': scheme,
        'backends': [{'group': f'{API}/{g}'} for g in groups],
    }


def _instances(neo4j_session, project, zone, names, status='RUNNING'):
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $project})
        UNWIND $names AS name
        MERGE (p)-[:RESOURCE]->(i:GCPInstance:GCPComputeInstance:Instance{id: $zone + '/instances/' + name})
        SET i.status = $status
        """,
        project=project, zone=zone, names=names, status=status,
    )


def _exposed_in(neo4j_session, project):
    rows = neo4j_session.run(
        """
        MATCH (:GCPProject{id: $project})-[:RESOURCE]->(n) WHERE n.exposed_internet
        RETURN [l IN labels(n) WHERE l STARTS WITH 'GCP' AND l <> 'GCPComputeInstance'][0] AS label,
            split(n.id, '/')[-1] AS name, n.exposed_internet_type AS types
        """,
        project=project,
    )
    return {(r['label'], r['name']): r['types'] for r in rows}


def _run_exposure_jobs(neo4j_session, project):
    run_analysis_job('gcp_load_balancer_exposure.json', neo4j_session, _params(project))
    run_analysis_job('gcp_compute_instance_analysis.json', neo4j_session, _params(project))


def test_unmanaged_instance_group_members_behind_an_external_backend_service_are_exposed(neo4j_session):
    project = 'proj-lb-members'
    zone = f'projects/{project}/zones/us-east1-b'
    _seed_project(neo4j_session, project)
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(
        neo4j_session,
        [
            _external_rule(
                project, 'ingress-fr', backend_services=[f'projects/{project}/global/backendServices/ingress'],
            ),
        ],
        TAG,
    )
    cartography.intel.gcp.cloudcdn.load_backend_services(
        neo4j_session, [
            # GKE Ingress: an unmanaged k8s-ig--* group per zone holding the cluster's nodes.
            _backend_service(project, 'ingress', 'EXTERNAL_MANAGED', [f'{zone}/instanceGroups/k8s-ig--abc']),
            _backend_service(project, 'internal', 'INTERNAL', [f'{zone}/instanceGroups/internal-ig']),
        ], project, TAG,
    )
    cartography.intel.gcp.loadbalancer.load_instance_groups(
        neo4j_session, [{'id': f'{zone}/instanceGroups/k8s-ig--abc'}, {'id': f'{zone}/instanceGroups/internal-ig'}],
        project, TAG,
    )
    _instances(neo4j_session, project, zone, ['node-1', 'internal-vm', 'left-group'])
    _instances(neo4j_session, project, zone, ['node-stopped'], status='TERMINATED')
    # Membership seen by an earlier sync; the VM has since left the group.
    neo4j_session.run(
        "MATCH (i:GCPInstance{id: $vm}), (ig:GCPInstanceGroup{id: $ig}) "
        "MERGE (i)-[r:MEMBER_OF_INSTANCE_GROUP]->(ig) SET r.lastupdated = 1",
        vm=f'{zone}/instances/left-group', ig=f'{zone}/instanceGroups/k8s-ig--abc',
    )
    client = MagicMock()
    client.instanceGroups.return_value.listInstances.return_value.execute.return_value = {
        'items': [{'instance': f'{API}/{zone}/instances/node-1'}, {'instance': f'{API}/{zone}/instances/node-stopped'}],
    }
    client.instanceGroups.return_value.listInstances_next.return_value = None

    cartography.intel.gcp.loadbalancer.sync_external_backend_members(neo4j_session, client, project, _params(project))
    _run_exposure_jobs(neo4j_session, project)

    # Only the group behind the external backend service is listed.
    client.instanceGroups.return_value.listInstances.assert_called_once_with(
        project=project, zone='us-east1-b', instanceGroup='k8s-ig--abc', body={'instanceState': 'ALL'},
    )
    members = neo4j_session.run(
        "MATCH (i:GCPInstance)-[:MEMBER_OF_INSTANCE_GROUP]->(:GCPInstanceGroup) WHERE i.id STARTS WITH $zone "
        "RETURN split(i.id, '/')[-1] AS name", zone=zone,
    ).value()
    assert sorted(members) == ['node-1', 'node-stopped']
    assert _exposed_in(neo4j_session, project) == {
        ('GCPForwardingRule', 'ingress-fr'): LB,
        ('GCPBackendService', 'ingress'): LB,
        ('GCPInstanceGroup', 'k8s-ig--abc'): LB,
        # No external IP needed; the stopped member and the internal backend's VM are not reachable.
        ('GCPInstance', 'node-1'): LB,
    }


def _neg(project, scope, name, neg_type, **fields):
    return {
        'name': name, 'networkEndpointType': neg_type,
        'selfLink': f'{API}/projects/{project}/{scope}/networkEndpointGroups/{name}', **fields,
    }


def test_network_endpoint_groups_behind_an_external_backend_service_expose_their_targets(neo4j_session):
    project = 'proj-lb-negs'
    zone = f'projects/{project}/zones/us-east1-b'
    region = f'projects/{project}/regions/us-east1'
    _seed_project(neo4j_session, project)
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(
        neo4j_session,
        [
            _external_rule(
                project, 'web-fr',
                backend_services=[
                    f'projects/{project}/global/backendServices/gke', f'projects/{project}/global/backendServices/fn',
                    f'projects/{project}/global/backendServices/run', f'projects/{project}/global/backendServices/cdn',
                ],
            ),
        ],
        TAG,
    )
    cartography.intel.gcp.cloudcdn.load_backend_services(
        neo4j_session, [
            # GKE container-native load balancing: a GCE_VM_IP_PORT NEG of pod endpoints on the node VMs.
            _backend_service(project, 'gke', 'EXTERNAL_MANAGED', [f'{zone}/networkEndpointGroups/k8s1-neg']),
            _backend_service(project, 'fn', 'EXTERNAL_MANAGED', [f'{region}/networkEndpointGroups/fn-neg']),
            _backend_service(project, 'run', 'EXTERNAL_MANAGED', [f'{region}/networkEndpointGroups/run-neg']),
            _backend_service(
                project, 'cdn', 'EXTERNAL_MANAGED', [f'projects/{project}/global/networkEndpointGroups/ext'],
            ),
            _backend_service(project, 'internal', 'INTERNAL_MANAGED', [f'{zone}/networkEndpointGroups/internal-neg']),
        ], project, TAG,
    )
    negs = [
        _neg(project, 'zones/us-east1-b', 'k8s1-neg', 'GCE_VM_IP_PORT', zone=f'{API}/{zone}'),
        _neg(project, 'zones/us-east1-b', 'internal-neg', 'GCE_VM_IP_PORT', zone=f'{API}/{zone}'),
        _neg(
            project, 'regions/us-east1', 'fn-neg', 'SERVERLESS', region=f'{API}/{region}',
            cloudFunction={'function': 'api'},
        ),
        _neg(
            project, 'regions/us-east1', 'run-neg', 'SERVERLESS', region=f'{API}/{region}',
            cloudRun={'service': 'web'},
        ),
        _neg(project, 'global', 'ext', 'INTERNET_FQDN_PORT'),
    ]
    loadbalancer = cartography.intel.gcp.loadbalancer
    loadbalancer.load_network_endpoint_groups(
        neo4j_session, loadbalancer.transform_network_endpoint_groups(negs, project), project, TAG,
    )
    _instances(neo4j_session, project, zone, ['gke-node-1', 'gke-node-2', 'internal-vm'])
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $project})
        UNWIND [['api', true], ['private-fn', false]] AS f
        MERGE (p)-[:RESOURCE]->(fn:GCPFunction{id: 'projects/' + $project + '/locations/us-east1/functions/' + f[0]})
        SET fn.exposed_internet = CASE WHEN f[1] THEN true END,
            fn.exposed_internet_type = CASE WHEN f[1] THEN ['allUsers'] END
        """,
        project=project,
    )
    client = MagicMock()
    client.networkEndpointGroups.return_value.listNetworkEndpoints.return_value.execute.return_value = {
        'items': [
            {'networkEndpoint': {'instance': 'gke-node-1', 'ipAddress': '10.8.0.4', 'port': 8080}},
            {'networkEndpoint': {'instance': 'gke-node-1', 'ipAddress': '10.8.0.5', 'port': 8080}},
        ],
    }
    client.networkEndpointGroups.return_value.listNetworkEndpoints_next.return_value = None

    loadbalancer.sync_external_backend_members(neo4j_session, client, project, _params(project))
    _run_exposure_jobs(neo4j_session, project)

    # Endpoints are listed for the external zonal VM NEG only.
    client.networkEndpointGroups.return_value.listNetworkEndpoints.assert_called_once_with(
        project=project, zone='us-east1-b', networkEndpointGroup='k8s1-neg', body={},
    )
    edge = neo4j_session.run(
        "MATCH (i:GCPInstance)-[r:MEMBER_OF_NETWORK_ENDPOINT_GROUP]->(neg) WHERE neg.id STARTS WITH $zone "
        "RETURN split(i.id, '/')[-1] AS vm, r.ip_addresses AS ips, r.ports AS ports", zone=zone,
    ).data()
    assert edge == [{'vm': 'gke-node-1', 'ips': ['10.8.0.4', '10.8.0.5'], 'ports': [8080]}]
    linked = neo4j_session.run(
        "MATCH (:GCPProject{id: $project})-[:RESOURCE]->(bs:GCPBackendService)-[:HAS_BACKEND]->(neg) "
        "OPTIONAL MATCH (neg)-[:SERVERLESS_TARGET]->(fn) RETURN bs.name AS bs, neg.name AS neg, fn.id AS fn",
        project=project,
    ).data()
    assert sorted((r['bs'], r['neg'], r['fn']) for r in linked) == [
        ('cdn', 'ext', None), ('fn', 'fn-neg', f'projects/{project}/locations/us-east1/functions/api'),
        ('gke', 'k8s1-neg', None), ('internal', 'internal-neg', None), ('run', 'run-neg', None),
    ]
    exposed = _exposed_in(neo4j_session, project)
    assert {k: v for k, v in exposed.items() if k[0] in ('GCPNetworkEndpointGroup', 'GCPInstance', 'GCPFunction')} == {
        ('GCPNetworkEndpointGroup', 'k8s1-neg'): LB,
        ('GCPNetworkEndpointGroup', 'fn-neg'): LB,
        ('GCPNetworkEndpointGroup', 'run-neg'): LB,
        ('GCPNetworkEndpointGroup', 'ext'): LB,
        # The node VM hosting the pod endpoints; the node with no endpoint and the internal NEG's VM are not.
        ('GCPInstance', 'gke-node-1'): LB,
        # Already public through IAM; the load balancer is a second way in. private-fn is not behind any NEG.
        ('GCPFunction', 'api'): ['allUsers', 'external_load_balancer'],
    }
    run_neg = neo4j_session.run(
        "MATCH (n:GCPNetworkEndpointGroup{name: 'run-neg'}) RETURN n.cloud_run_service AS svc, n.region AS region",
    ).single()
    assert (run_neg['svc'], run_neg['region']) == ('web', 'us-east1')


def test_stale_network_endpoint_groups_and_links_are_cleaned_up(neo4j_session):
    project = 'proj-lb-neg-cleanup'
    zone = f'projects/{project}/zones/us-east1-b'
    _seed_project(neo4j_session, project)
    neo4j_session.run(
        """
        MATCH (p:GCPProject{id: $project})
        MERGE (p)-[:RESOURCE]->(gone:GCPNetworkEndpointGroup{id: $zone + '/networkEndpointGroups/gone'})
        SET gone.lastupdated = 1
        MERGE (p)-[:RESOURCE]->(kept:GCPNetworkEndpointGroup{id: $zone + '/networkEndpointGroups/kept'})
        SET kept.lastupdated = $tag
        MERGE (p)-[:RESOURCE]->(i:GCPInstance{id: $zone + '/instances/vm'})
        MERGE (i)-[e:MEMBER_OF_NETWORK_ENDPOINT_GROUP]->(kept) SET e.lastupdated = 1
        MERGE (p)-[:RESOURCE]->(bs:GCPBackendService{id: 'projects/' + $project + '/global/backendServices/bs'})
        MERGE (bs)-[h:HAS_BACKEND]->(kept) SET h.lastupdated = 1
        """,
        project=project, zone=zone, tag=TAG,
    )

    run_cleanup_job('gcp_network_endpoint_groups_cleanup.json', neo4j_session, _params(project))
    run_cleanup_job('gcp_lb_backend_members_cleanup.json', neo4j_session, _params(project))

    rows = neo4j_session.run(
        "MATCH (:GCPProject{id: $project})-[:RESOURCE]->(n:GCPNetworkEndpointGroup) "
        "RETURN n.id AS id, COUNT { (n)<-[]-(:GCPInstance|GCPBackendService) } AS links",
        project=project,
    ).data()
    assert rows == [{'id': f'{zone}/networkEndpointGroups/kept', 'links': 0}]


def test_backend_services_referenced_from_another_project_of_this_workspace_are_exposed(neo4j_session):
    # Front end (rule + URL map) in proj-xp-front; backend services and VMs in proj-xp-back. Both synced by
    # ws-lb. proj-xp-foreign shares the org node but is synced only by another workspace.
    front, back, foreign = 'proj-xp-front', 'proj-xp-back', 'proj-xp-foreign'
    zone = f'projects/{back}/zones/us-east1-b'
    _seed_project(neo4j_session, front)
    _seed_project(neo4j_session, back)
    _seed_project(neo4j_session, foreign, workspace='ws-lb-other')
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(
        neo4j_session, [_external_rule(front, 'xp-fr', url_map=f'projects/{front}/global/urlMaps/xp')], TAG,
    )
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(
        neo4j_session,
        [
            _external_rule(
                foreign, 'foreign-fr', backend_services=[f'projects/{back}/global/backendServices/via-foreign'],
            ),
        ],
        TAG,
    )
    cartography.intel.gcp.loadbalancer.load_url_maps(
        neo4j_session, [{
            'id': f'projects/{front}/global/urlmaps/xp', 'name': 'xp',
            'selfLink': f'{API}/projects/{front}/global/urlMaps/xp',
            'defaultService': f'{API}/projects/{back}/global/backendServices/shared',
        }], front, TAG,
    )
    cartography.intel.gcp.cloudcdn.load_backend_services(
        neo4j_session, [
            _backend_service(back, 'shared', 'EXTERNAL_MANAGED', [f'{zone}/instanceGroups/shared-ig']),
            _backend_service(back, 'via-foreign', 'EXTERNAL_MANAGED', [f'{zone}/instanceGroups/foreign-ig']),
        ], back, TAG,
    )
    cartography.intel.gcp.loadbalancer.load_instance_groups(
        neo4j_session, [{'id': f'{zone}/instanceGroups/shared-ig'}, {'id': f'{zone}/instanceGroups/foreign-ig'}],
        back, TAG,
    )
    _instances(neo4j_session, back, zone, ['shared-vm', 'foreign-vm'])
    neo4j_session.run(
        """
        UNWIND [['shared-vm', 'shared-ig'], ['foreign-vm', 'foreign-ig']] AS m
        MATCH (i:GCPInstance{id: $zone + '/instances/' + m[0]})
        MATCH (ig:GCPInstanceGroup{id: $zone + '/instanceGroups/' + m[1]})
        MERGE (i)-[r:MEMBER_OF_INSTANCE_GROUP]->(ig) SET r.lastupdated = $tag
        """,
        zone=zone, tag=TAG,
    )

    _run_exposure_jobs(neo4j_session, front)
    # The front project's run never writes the other project's backends.
    assert _exposed_in(neo4j_session, back) == {}
    _run_exposure_jobs(neo4j_session, back)

    assert _exposed_in(neo4j_session, back) == {
        ('GCPBackendService', 'shared'): LB,
        ('GCPInstanceGroup', 'shared-ig'): LB,
        ('GCPInstance', 'shared-vm'): LB,
    }
    assert _exposed_in(neo4j_session, front) == {('GCPForwardingRule', 'xp-fr'): LB, ('GCPUrlMap', 'xp'): LB}


def test_vm_behind_external_protocol_forwarding_is_exposed(neo4j_session):
    project = 'proj-lb-ti'
    zone = f'projects/{project}/zones/us-east1-b'
    _seed_project(neo4j_session, project)
    response = {
        'id': f'projects/{project}/regions/us-east1/forwardingRules', 'items': [{
            'name': 'pf-fr', 'loadBalancingScheme': 'EXTERNAL', 'region': f'{API}/projects/{project}/regions/us-east1',
            'selfLink': f'{API}/projects/{project}/regions/us-east1/forwardingRules/pf-fr',
            'target': f'{API}/{zone}/targetInstances/ti',
        }],
    }
    client = MagicMock()
    client.targetInstances.return_value.get.return_value.execute.return_value = {
        'instance': f'{API}/{zone}/instances/vm-ti',
    }
    rules = cartography.intel.gcp.compute.transform_gcp_forwarding_rules(response)
    cartography.intel.gcp.compute.resolve_external_lb_backends(client, rules)
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(neo4j_session, rules, TAG)
    _instances(neo4j_session, project, zone, ['vm-ti', 'vm-other'])

    _run_exposure_jobs(neo4j_session, project)

    assert _exposed_in(neo4j_session, project) == {('GCPForwardingRule', 'pf-fr'): LB, ('GCPInstance', 'vm-ti'): LB}


def test_regional_ssl_policy_of_an_external_regional_https_proxy_is_exposed(neo4j_session):
    project = 'proj-lb-rssl'
    region = f'projects/{project}/regions/us-east1'
    _seed_project(neo4j_session, project)
    response = {
        'id': f'{region}/forwardingRules', 'items': [{
            'name': 'rhttps-fr', 'loadBalancingScheme': 'EXTERNAL_MANAGED', 'region': f'{API}/{region}',
            'selfLink': f'{API}/{region}/forwardingRules/rhttps-fr', 'target': f'{API}/{region}/targetHttpsProxies/rp',
        }],
    }
    client = MagicMock()
    client.regionTargetHttpsProxies.return_value.get.return_value.execute.return_value = {
        'sslPolicy': f'{API}/{region}/sslPolicies/regional',
    }
    rules = cartography.intel.gcp.compute.transform_gcp_forwarding_rules(response)
    cartography.intel.gcp.compute.resolve_external_lb_backends(client, rules)
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(neo4j_session, rules, TAG)
    loadbalancer = cartography.intel.gcp.loadbalancer
    loadbalancer.load_ssl_policies(
        neo4j_session,
        loadbalancer.transform_ssl_policies(
            [
                {'name': 'regional', 'region': f'{API}/{region}'},
                {'name': 'regional-unused', 'region': f'{API}/{region}'},
            ],
            project,
        ),
        project, TAG,
    )

    _run_exposure_jobs(neo4j_session, project)

    assert _exposed_in(neo4j_session, project) == {
        ('GCPForwardingRule', 'rhttps-fr'): LB, ('GCPSSLPolicy', 'regional'): LB,
    }
