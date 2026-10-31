"""
End-to-end check of the GCP exposure layers on a graph built by the GCP loaders.
Scenarios follow docs/exposure-layers/plan.md section 8 where the construct exists in GCP.
"""
from unittest.mock import MagicMock
from unittest.mock import patch

import cartography.intel.gcp.cloudcdn
import cartography.intel.gcp.cloudrun
import cartography.intel.gcp.compute
import cartography.intel.gcp.instance_groups
import cartography.intel.gcp.loadbalancer
from cartography.intel.gcp import exposure_layers

TAG = 1700000000
WS, ORG, PROJECT = 'ws-gxl', 'org-gxl', 'proj-gxl'
OTHER_WS, OTHER_ORG, OTHER_PROJECT = 'ws-gxl-other', 'org-gxl-other', 'proj-gxl-other'
PARAMS = {'UPDATE_TAG': TAG, 'WORKSPACE_ID': WS, 'GCP_ORGANIZATION_ID': ORG, 'GCP_PROJECT_ID': PROJECT}
API = 'https://www.googleapis.com/compute/v1'
MAIN, NOROUTE = 'main', 'noroute'
ZONE = f'projects/{PROJECT}/zones/us-east1-b'
GFE = ['130.211.0.0/22', '35.191.0.0/16']
DB_SA = 'app@proj-gxl.iam.gserviceaccount.com'
FR_ID = f'projects/{PROJECT}/locations/global/forwardingRules/https-fr'


def _run(session, query, **kw):
    session.run(query, **kw).consume()


def _seed_tenants(session):
    for ws, org, project in ((WS, ORG, PROJECT), (OTHER_WS, OTHER_ORG, OTHER_PROJECT)):
        _run(
            session,
            """
            MERGE (w:CloudanixWorkspace{id: $ws})-[:OWNER]->(o:GCPOrganization{id: $org})
            MERGE (o)-[:OWNER]->(p:GCPProject{id: $project}) SET p.workspace_ids = [$ws]
            """,
            ws=ws, org=org, project=project,
        )
        cartography.intel.gcp.compute.load_gcp_vpcs(
            session, cartography.intel.gcp.compute.transform_gcp_vpcs({
                'id': f'projects/{project}/global/networks',
                'items': [
                    {'name': n, 'selfLink': f'{API}/projects/{project}/global/networks/{n}'} for n in (MAIN, NOROUTE)
                ],
            }), TAG,
        )


def _firewall(project, name, network, priority=1000, ranges=('0.0.0.0/0',), allowed=None, denied=None, **kw):
    fw = {
        'name': name, 'network': f'{API}/projects/{project}/global/networks/{network}', 'direction': 'INGRESS',
        'priority': priority, 'disabled': False, 'selfLink': f'{API}/projects/{project}/global/firewalls/{name}',
        'sourceRanges': list(ranges), **kw,
    }
    if allowed is not None:
        fw['allowed'] = allowed
    if denied is not None:
        fw['denied'] = denied
    return fw


def _load_firewalls(session, project, items):
    response = {'id': f'projects/{project}/global/firewalls', 'items': items}
    fws = cartography.intel.gcp.compute.transform_gcp_firewall(response)
    cartography.intel.gcp.compute.load_gcp_ingress_firewalls(session, fws, TAG)


def _load_routes(session, project):
    def route(name, network, dest, gateway=None):
        r = {
            'name': name, 'network': f'{API}/projects/{project}/global/networks/{network}', 'destRange': dest,
            'priority': 1000 if gateway else 0,
        }
        if gateway:
            r['nextHopGateway'] = f'{API}/projects/{project}/global/gateways/default-internet-gateway'
        else:
            r['nextHopNetwork'] = r['network']
        return r
    routes = [
        route('main-subnet', MAIN, '10.0.0.0/24'),
        route('main-default', MAIN, '0.0.0.0/0', gateway=True),
        # The default internet route of this network was deleted; only the subnet route is left.
        route('noroute-subnet', NOROUTE, '10.1.0.0/24'),
    ]
    cartography.intel.gcp.compute.load_gcp_routes(
        session, cartography.intel.gcp.compute.transform_gcp_routes(routes, project), TAG,
    )


def _instance(project, name, network, tags=(), nat_ip=None, sa=None, image='debian-12-bookworm-v20240101'):
    nic = {
        'name': 'nic0', 'network': f'{API}/projects/{project}/global/networks/{network}',
        'subnetwork': f'{API}/projects/{project}/regions/us-east1/subnetworks/{network}', 'networkIP': '10.0.0.5',
        'accessConfigs': [{'type': 'ONE_TO_ONE_NAT', 'name': 'External NAT', 'natIP': nat_ip}] if nat_ip else [],
    }
    return {
        'name': name, 'id': name, 'status': 'RUNNING', 'zone': f'{API}/projects/{project}/zones/us-east1-b',
        'selfLink': f'{API}/projects/{project}/zones/us-east1-b/instances/{name}',
        'tags': {'items': list(tags)}, 'networkInterfaces': [nic],
        'serviceAccounts': [{'email': sa}] if sa else [],
        'disks': [{
            'boot': True, 'initializeParams': {'sourceImage': f'{API}/projects/debian-cloud/global/images/{image}'},
        }],
    }


def _load_instances(session, items):
    # Console links are not under test; older cloudconsolelink builds lack the compute_image kwargs.
    with patch.object(cartography.intel.gcp.compute.gcp_console_link, 'get_console_link', return_value='link'):
        instances = cartography.intel.gcp.compute.transform_gcp_instances(items, None)
    cartography.intel.gcp.compute.load_gcp_instances(session, instances, TAG)


def _load_https_lb(session):
    """External HTTPS LB -> URL map -> backend service (portName http) -> MIG (http:8080) -> lb-backend."""
    response = {
        'id': f'projects/{PROJECT}/global/forwardingRules', 'items': [{
            'name': 'https-fr', 'loadBalancingScheme': 'EXTERNAL_MANAGED', 'IPProtocol': 'TCP', 'portRange': '443-443',
            'selfLink': f'{API}/projects/{PROJECT}/global/forwardingRules/https-fr',
            'target': f'{API}/projects/{PROJECT}/global/targetHttpsProxies/web-https',
        }],
    }
    client = MagicMock()
    client.targetHttpsProxies.return_value.get.return_value.execute.return_value = {
        'urlMap': f'{API}/projects/{PROJECT}/global/urlMaps/web',
    }
    rules = cartography.intel.gcp.compute.transform_gcp_forwarding_rules(response)
    cartography.intel.gcp.compute.resolve_external_lb_backends(client, rules)
    cartography.intel.gcp.compute.load_gcp_forwarding_rules(session, rules, TAG)
    cartography.intel.gcp.loadbalancer.load_url_maps(
        session, [{
            'id': f'projects/{PROJECT}/global/urlmaps/web', 'name': 'web',
            'selfLink': f'{API}/projects/{PROJECT}/global/urlMaps/web',
            'defaultService': f'{API}/projects/{PROJECT}/global/backendServices/web',
        }], PROJECT, TAG,
    )
    cartography.intel.gcp.cloudcdn.load_backend_services(
        session, [{
            'id': f'projects/{PROJECT}/global/backendServices/web', 'name': 'web', 'portName': 'http',
            'iap': {'enabled': True}, 'backends': [{'group': f'{API}/{ZONE}/instanceGroups/web-mig'}],
        }], PROJECT, TAG,
    )
    cartography.intel.gcp.loadbalancer.load_instance_groups(
        session, [{
            'id': f'{ZONE}/instanceGroups/web-mig', 'namedPorts': [{'name': 'http', 'port': 8080}],
        }], PROJECT, TAG,
    )
    ig = cartography.intel.gcp.instance_groups
    mig_id = f'{API}/{ZONE}/instanceGroupManagers/web-mig'
    ig._load_managed_instance_groups(
        session, [{'id': mig_id, 'name': 'web-mig', 'instance_group': f'{ZONE}/instanceGroups/web-mig'}], PROJECT, TAG,
    )
    ig._load_vm_to_mig_part_of_relationships(
        session, [{'vm_self_link': f'{API}/{ZONE}/instances/lb-backend', 'mig_id': mig_id}], TAG,
    )


def _load_managed_services(session):
    services = cartography.intel.gcp.cloudrun.transform_services(
        [
            {
                'metadata': {
                    'name': name, 'labels': {'cloud.googleapis.com/location': 'us-east1'},
                    'annotations': {'run.googleapis.com/ingress': ingress},
                },
                'status': {'url': f'https://{name}.run.app'},
            }
            for name, ingress in (('run-public', 'all'), ('run-internal', 'internal'))
        ], PROJECT,
    )
    for service in services:
        service['invoker_members'] = ['allUsers']
    cartography.intel.gcp.cloudrun.load_cloudrun_services(session, services, PROJECT, TAG)
    _run(
        session,
        """
        MATCH (p:GCPProject{id: $project})
        MERGE (p)-[:RESOURCE]->(s:GCPSQLInstance{id: 'sql-pg'})
        SET s.databaseVersion = 'POSTGRES_15', s.ipV4Enabled = true, s.public_ip = '34.1.1.1', s.port = 5432,
            s.authorized_networks = ['0.0.0.0/0'], s.private_ip = '10.9.0.3',
            s.vpcNetworkID = 'projects/' + $project + '/global/networks/main'
        MERGE (p)-[:RESOURCE]->(b:GCPBucket{id: 'public-bucket'}) SET b.uniform_bucket_level_access = true
        MERGE (b)-[:ATTACHED_BINDING]->(:GCPBucketPolicyBinding{id: 'pb', role: 'roles/storage.objectViewer',
            members: ['allUsers']})
        """,
        project=PROJECT,
    )


def _build(session):
    session.run('MATCH (n) DETACH DELETE n').consume()
    _seed_tenants(session)
    _load_firewalls(
        session, PROJECT, [
            _firewall(PROJECT, 'web-443', MAIN, allowed=[{'IPProtocol': 'tcp', 'ports': ['443']}], targetTags=['web']),
            _firewall(
                PROJECT, 'internal-ssh', MAIN, ranges=('10.0.0.0/8',), allowed=[{'IPProtocol': 'tcp', 'ports': ['22']}],
                targetTags=['internal'],
            ),
            _firewall(
                PROJECT, 'locked-allow', MAIN, allowed=[{'IPProtocol': 'tcp', 'ports': ['80']}], targetTags=['locked'],
            ),
            _firewall(
                PROJECT, 'locked-deny', MAIN, priority=500, denied=[{'IPProtocol': 'tcp', 'ports': ['80']}],
                targetTags=['locked'],
            ),
            _firewall(
                PROJECT, 'tie-allow', MAIN, priority=900, allowed=[{'IPProtocol': 'tcp', 'ports': ['8080']}],
                targetTags=['tie'],
            ),
            _firewall(PROJECT, 'tie-deny', MAIN, priority=900, denied=[{'IPProtocol': 'all'}], targetTags=['tie']),
            _firewall(
                PROJECT, 'gfe-8080', MAIN, ranges=GFE, allowed=[{'IPProtocol': 'tcp', 'ports': ['8080']}],
                targetTags=['lb-backend'],
            ),
            _firewall(
                PROJECT, 'db-from-app', MAIN, ranges=(), sourceServiceAccounts=[DB_SA],
                allowed=[{'IPProtocol': 'tcp', 'ports': ['5432']}], targetTags=['db'],
            ),
            _firewall(PROJECT, 'noroute-all', NOROUTE, allowed=[{'IPProtocol': 'all'}]),
        ],
    )
    _load_firewalls(
        session, OTHER_PROJECT, [_firewall(OTHER_PROJECT, 'other-all', MAIN, allowed=[{'IPProtocol': 'all'}])],
    )
    _load_routes(session, PROJECT)
    _load_routes(session, OTHER_PROJECT)
    _load_instances(
        session, [
            _instance(PROJECT, 'open', MAIN, tags=['web'], nat_ip='34.0.0.1', image='ubuntu-2204-jammy-v20240101'),
            _instance(PROJECT, 'rfc1918', MAIN, tags=['internal'], nat_ip='34.0.0.2'),
            _instance(PROJECT, 'locked', MAIN, tags=['locked'], nat_ip='34.0.0.3'),
            _instance(PROJECT, 'tie', MAIN, tags=['tie'], nat_ip='34.0.0.4'),
            _instance(PROJECT, 'noroute', NOROUTE, nat_ip='34.0.0.5'),
            _instance(PROJECT, 'lb-backend', MAIN, tags=['lb-backend']),
            _instance(PROJECT, 'db', MAIN, tags=['db']),
            _instance(PROJECT, 'app', MAIN, sa=DB_SA),
            _instance(OTHER_PROJECT, 'other-open', MAIN, nat_ip='34.0.0.9'),
        ],
    )
    _load_https_lb(session)
    _load_managed_services(session)
    _run(
        session,
        """
        MATCH (a:GCPInstance{instancename: 'open'}), (b:GCPInstance{instancename: 'noroute'})
        MERGE (a)-[r:CAN_NETWORK_REACH]->(b) SET r.lastupdated = 1, r.ports = ['tcp:22-22']
        SET a.exposed_internet = true, a.exposed_internet_type = ['legacy']
        WITH b MATCH (s:GCPInstance{instancename: 'rfc1918'}) SET s.internet_reachable = true
        """,
    )


def _props(session, name, label='GCPInstance', key='instancename'):
    record = session.run(f'MATCH (n:{label}{{{key}: $name}}) RETURN properties(n) AS p', name=name).single()
    return record['p']


def _edges(session):
    rows = session.run(
        "MATCH (a:GCPInstance)-[r:CAN_NETWORK_REACH]->(b) RETURN coalesce(a.instancename, a.id) AS src, "
        "coalesce(b.instancename, b.id) AS dst, r.ports AS ports, r.via AS via",
    )
    return {(r['src'], r['dst']): (sorted(r['ports']), r['via']) for r in rows}


def test_gcp_exposure_layers_end_to_end(neo4j_session):
    _build(neo4j_session)
    exposure_layers.run(neo4j_session, PARAMS)
    s = neo4j_session

    open_vm = _props(s, 'open')
    assert open_vm['public_reasons'] == ['external_ip']
    assert open_vm['internet_reachable'] is True
    assert open_vm['internet_reachable_ports'] == ['tcp:443-443']
    assert open_vm['internet_reachable_via'] == ['direct_ipv4']
    assert open_vm['access_auth'] == 'unknown'
    assert open_vm['software_identity'] == ['ubuntu@22.04']
    assert open_vm['software_identity_source'] == 'image_name'
    # Legacy flags are not ours to touch.
    assert open_vm['exposed_internet'] is True and open_vm['exposed_internet_type'] == ['legacy']

    for name in ('rfc1918', 'noroute', 'locked', 'tie'):
        props = _props(s, name)
        assert props['public_reasons'] == ['external_ip'], name
        assert props['internet_reachable'] is False, name
        assert props['internet_reachable_ports'] == [], name

    backend = _props(s, 'lb-backend')
    assert backend['public_reasons'] == []
    assert backend['internet_reachable_ports'] == ['tcp:8080-8080']
    assert backend['internet_reachable_via'] == [f'forwarding_rule:{FR_ID}']

    fr = _props(s, FR_ID, 'GCPForwardingRule', 'id')
    assert fr['internet_reachable_ports'] == ['tcp:443-443'] and fr['public_reasons'] == ['external_forwarding_rule']
    bs = _props(s, f'projects/{PROJECT}/global/backendServices/web', 'GCPBackendService', 'id')
    assert bs['internet_reachable'] is True and bs['access_auth'] == 'required' and bs['access_auth_reasons'] == ['iap']

    run_public = _props(s, f'projects/{PROJECT}/services/run-public', 'GCPCloudRunService', 'id')
    run_internal = _props(s, f'projects/{PROJECT}/services/run-internal', 'GCPCloudRunService', 'id')
    assert run_public['internet_reachable'] is True and run_public['access_auth'] == 'none'
    assert run_internal['internet_reachable'] is False

    sql = _props(s, 'sql-pg', 'GCPSQLInstance', 'id')
    assert sql['internet_reachable_ports'] == ['tcp:5432-5432']
    assert sql['access_auth'] == 'required' and sql['software_identity'] == ['postgres@15']

    bucket = _props(s, 'public-bucket', 'GCPBucket', 'id')
    assert bucket['access_auth'] == 'none' and bucket['public_reasons'] == ['public_iam_or_acl']
    assert bucket['internet_reachable_ports'] == ['tcp:443-443']

    edges = _edges(s)
    # Stale edge from an earlier run is gone; identity-sourced firewall gives app -> db.
    assert ('open', 'noroute') not in edges
    assert edges[('app', 'db')] == (['tcp:5432-5432'], 'firewall_source_tag_or_sa')
    main_vms = {'open', 'rfc1918', 'locked', 'tie', 'lb-backend', 'db', 'app'}
    assert {src for src, dst in edges if dst == 'sql-pg'} == main_vms
    assert len(edges) == len(main_vms) + 1

    other = _props(s, 'other-open')
    assert 'internet_reachable' not in other and 'access_auth' not in other


def test_gcp_exposure_layers_rerun_is_stable(neo4j_session):
    _build(neo4j_session)
    exposure_layers.run(neo4j_session, PARAMS)
    first = {name: _props(neo4j_session, name) for name in ('open', 'lb-backend', 'tie')}
    first_edges = _edges(neo4j_session)
    exposure_layers.run(neo4j_session, {**PARAMS, 'UPDATE_TAG': TAG + 1})
    second = {name: _props(neo4j_session, name) for name in ('open', 'lb-backend', 'tie')}
    for name in first:
        for key in ('internet_reachable', 'internet_reachable_ports', 'internet_reachable_via', 'public_reasons'):
            assert first[name][key] == second[name][key]
    assert _edges(neo4j_session) == first_edges
