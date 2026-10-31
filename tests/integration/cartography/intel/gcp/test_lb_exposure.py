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
