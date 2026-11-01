"""
End-to-end check of the GCP exposure layers on a graph built by the GCP loaders.
Scenarios follow docs/exposure-layers/plan.md section 8 where the construct exists in GCP.
"""
import json
from unittest.mock import MagicMock
from unittest.mock import patch

from googleapiclient.errors import HttpError

import cartography.intel.gcp.cloudcdn
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
RUN_PUBLIC = f'projects/{PROJECT}/locations/us-east1/services/run-public'
RUN_INTERNAL = f'projects/{PROJECT}/locations/us-east1/services/run-internal'
RUN_LB = f'projects/{PROJECT}/locations/us-east1/services/run-lb'
RUN_LB_ORPHAN = f'projects/{PROJECT}/locations/us-east1/services/run-lb-orphan'
RUN_LB_WEST = f'projects/{PROJECT}/locations/us-west1/services/run-lb-west'
RUN_NEG = f'{API}/projects/{PROJECT}/regions/us-east1/networkEndpointGroups/run-neg'
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
            'iap': {'enabled': True},
            'backends': [{'group': f'{API}/{ZONE}/instanceGroups/web-mig'}, {'group': RUN_NEG}],
        }], PROJECT, TAG,
    )
    # Serverless NEG: the LB fronts RUN_LB, whose ingress admits only load balancers.
    lbm = cartography.intel.gcp.loadbalancer
    lbm.load_network_endpoint_groups(
        session, lbm.transform_network_endpoint_groups(
            [
                {
                    'selfLink': RUN_NEG, 'name': 'run-neg', 'networkEndpointType': 'SERVERLESS',
                    'region': f'{API}/projects/{PROJECT}/regions/us-east1', 'cloudRun': {'service': 'run-lb'},
                }, {
                    # us-west1's regional list failed this sync: only a zonal NEG there is left in the graph.
                    'selfLink': f'{API}/projects/{PROJECT}/zones/us-west1-a/networkEndpointGroups/vm-neg',
                    'name': 'vm-neg', 'networkEndpointType': 'GCE_VM_IP_PORT',
                    'zone': f'{API}/projects/{PROJECT}/zones/us-west1-a',
                },
            ], PROJECT,
        ), PROJECT, TAG,
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
    # Shape written by cloudrun.py once PR #507 lands: ingress null means "all".
    _run(
        session,
        """
        MATCH (p:GCPProject{id: $project})
        UNWIND $services AS svc
            MERGE (p)-[:RESOURCE]->(s:GCPCloudRunService{id: svc.id})
            SET s.url = svc.url, s.ingress = svc.ingress, s.iam_policy_status = svc.status,
                s.public_invokers = svc.invokers, s.region = coalesce(svc.region, 'us-east1')
        """,
        project=PROJECT,
        services=[
            {
                'id': RUN_PUBLIC, 'url': 'https://run-public.run.app', 'ingress': None, 'status': 'resolved',
                'invokers': ['allUsers'],
            },
            {
                'id': RUN_INTERNAL, 'url': 'https://run-internal.run.app', 'ingress': 'internal',
                'status': 'not_needed', 'invokers': [],
            },
            {
                'id': RUN_LB, 'url': 'https://run-lb.run.app', 'ingress': 'internal-and-cloud-load-balancing',
                'status': 'resolved', 'invokers': ['allUsers'],
            },
            {
                'id': RUN_LB_ORPHAN, 'url': 'https://run-lb-orphan.run.app',
                'ingress': 'internal-and-cloud-load-balancing', 'status': 'resolved', 'invokers': ['allUsers'],
            },
            {
                'id': RUN_LB_WEST, 'url': 'https://run-lb-west.run.app', 'region': 'us-west1',
                'ingress': 'internal-and-cloud-load-balancing', 'status': 'resolved', 'invokers': ['allUsers'],
            },
        ],
    )
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

    run_public = _props(s, RUN_PUBLIC, 'GCPCloudRunService', 'id')
    run_internal = _props(s, RUN_INTERNAL, 'GCPCloudRunService', 'id')
    assert run_public['internet_reachable'] is True and run_public['access_auth'] == 'none'
    assert run_internal['internet_reachable'] is False and run_internal['access_auth'] == 'unknown'
    # Ingress internal-and-cloud-load-balancing: reachable only through a NEG behind an external LB.
    run_lb = _props(s, RUN_LB, 'GCPCloudRunService', 'id')
    assert run_lb['internet_reachable_via'] == [f'forwarding_rule:{FR_ID}']
    assert run_lb['internet_reachable_ports'] == ['tcp:443-443']
    assert _props(s, RUN_LB_ORPHAN, 'GCPCloudRunService', 'id')['internet_reachable'] is False
    # No serverless NEG in us-west1 (the zonal one does not count): a load balancer may still front it.
    run_lb_west = _props(s, RUN_LB_WEST, 'GCPCloudRunService', 'id')
    assert run_lb_west['internet_reachable_via'] == ['load_balancer_unresolved']

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
    assert 'exposure_evaluated_at' not in other


def _json(props, key):
    return json.loads(props[key])


def test_gcp_exposure_context_paths_blockers_and_summaries(neo4j_session):
    _build(neo4j_session)
    exposure_layers.run(neo4j_session, PARAMS)
    s = neo4j_session

    open_vm = _props(s, 'open')
    assert open_vm['exposure_evaluated_at'] == TAG
    assert _json(open_vm, 'exposure_blocked_by') == []
    assert _json(open_vm, 'exposure_paths') == [{
        'via': 'direct_ipv4', 'entry': {'type': 'external_ip', 'id': '34.0.0.1'}, 'ports': ['tcp:443-443'],
        'hops': [
            {'hop': 'network', 'id': MAIN_URI},
            {'hop': 'route', 'id': 'main-default', 'rule': '0.0.0.0/0 -> default-internet-gateway'},
            {'hop': 'firewall', 'id': 'web-443'},
        ],
    }]

    blockers = {name: _json(_props(s, name), 'exposure_blocked_by') for name in ('noroute', 'rfc1918', 'locked', 'tie')}
    noroute_uri = f'projects/{PROJECT}/global/networks/{NOROUTE}'
    assert blockers['noroute'] == [{
        'hop': 'route', 'id': None, 'reason': 'no_internet_route',
        'detail': f'no 0.0.0.0/0 route to default-internet-gateway in {noroute_uri}',
    }]
    assert blockers['rfc1918'] == [{'hop': 'firewall', 'id': MAIN_URI, 'reason': 'not_allowed'}]
    assert blockers['locked'] == [{'hop': 'firewall', 'id': 'locked-deny', 'reason': 'denied'}]
    assert blockers['tie'] == [{'hop': 'firewall', 'id': 'tie-deny', 'reason': 'denied'}]

    backend_paths = _json(_props(s, 'lb-backend'), 'exposure_paths')
    listener = {'hop': 'listener', 'id': FR_ID, 'rule': '443-443'}
    assert backend_paths == [{
        'via': f'forwarding_rule:{FR_ID}', 'ports': ['tcp:8080-8080'],
        'entry': {'type': 'forwarding_rule', 'id': FR_ID, 'listener_ports': ['tcp:443-443']},
        'hops': [
            listener, {'hop': 'backend', 'id': f'projects/{PROJECT}/global/backendServices/web'},
            {'hop': 'target_group', 'id': f'{ZONE}/instanceGroups/web-mig'},
            {'hop': 'network', 'id': MAIN_URI}, {'hop': 'firewall', 'id': 'gfe-8080'},
        ],
    }]
    assert _json(_props(s, FR_ID, 'GCPForwardingRule', 'id'), 'exposure_paths')[0]['hops'] == [listener]

    app = _props(s, 'app')
    assert app['network_reachable_data_store_count'] == 2
    assert _json(app, 'network_reachable_data_stores') == [
        {
            'id': f'{ZONE}/instances/db', 'type': 'GCPInstance', 'ports': ['tcp:5432-5432'],
            'via': 'firewall_source_tag_or_sa', 'admitted_by': 'db-from-app',
        },
        {'id': 'sql-pg', 'type': 'GCPSQLInstance', 'ports': ['tcp:5432-5432'], 'via': 'private_service_access'},
    ]
    assert _props(s, 'noroute')['network_reachable_data_store_count'] == 0
    sql = _props(s, 'sql-pg', 'GCPSQLInstance', 'id')
    # open (direct) and lb-backend (via the LB) are internet-reachable among the 7 main-network VMs.
    assert (sql['network_reachable_from_count'], sql['network_reachable_from_internet_exposed_count']) == (7, 2)
    assert sql['exposure_evaluated_at'] == TAG
    db = _props(s, 'db')
    assert (db['network_reachable_from_count'], db['network_reachable_from_internet_exposed_count']) == (1, 0)


BLOCKED_SA, OPENED_SA, NETPOL_SA, LOCKED_DB_SA = (
    f'{n}@{PROJECT}.iam.gserviceaccount.com' for n in (
        'blocked', 'opened', 'netpol', 'lockeddb',
    )
)
MAIN_URI = f'projects/{PROJECT}/global/networks/{MAIN}'
VPC_LIST = [{'name': n, 'partial_uri': f'projects/{PROJECT}/global/networks/{n}'} for n in (MAIN, NOROUTE)]


def _policy_rule(priority, action, l4, sa, ranges=('0.0.0.0/0',)):
    return {
        'priority': priority, 'action': action, 'direction': 'INGRESS', 'targetServiceAccounts': [sa],
        'match': {'srcIpRanges': list(ranges), 'layer4Configs': l4},
    }


MAIN_POLICIES = {
    'firewallPolicys': [
        {
            'name': '9001', 'shortName': 'org-baseline', 'type': 'HIERARCHY', 'rules': [
                _policy_rule(100, 'deny', [{'ipProtocol': 'tcp', 'ports': ['443']}], BLOCKED_SA),
                _policy_rule(200, 'allow', [{'ipProtocol': 'tcp', 'ports': ['8443']}], OPENED_SA),
                _policy_rule(300, 'deny', [{'ipProtocol': 'all'}], LOCKED_DB_SA),
            ],
        },
        {
            'name': 'main-netpol', 'type': 'NETWORK', 'priority': 1000, 'rules': [
                _policy_rule(10, 'deny', [{'ipProtocol': 'tcp', 'ports': ['443']}], NETPOL_SA),
            ],
        },
    ],
}


def _compute(responses):
    """Compute client whose getEffectiveFirewalls answers per network; a missing network is refused (403)."""
    def call(project, network):
        if network not in responses:
            raise HttpError(MagicMock(status=403), b'{"error": {"status": "PERMISSION_DENIED"}}')
        return MagicMock(execute=MagicMock(return_value=responses[network]))
    compute = MagicMock()
    compute.networks.return_value.getEffectiveFirewalls.side_effect = call
    return compute


def _sync_policies(session, responses, tag=TAG):
    cartography.intel.gcp.compute.sync_gcp_firewall_policies(
        session, _compute(responses), PROJECT, VPC_LIST, tag, {**PARAMS, 'UPDATE_TAG': tag, 'LIMIT_SIZE': 1000},
    )


def _policy_rules(session):
    rows = session.run(
        'MATCH (v:GCPVpc)-[:RESOURCE]->(r:GCPFirewallPolicyRule) RETURN v.id AS vpc, r.id AS id, r.action AS action, '
        'r.policy_type AS type, r.policy_order AS ord, r.entries AS entries, r.target_service_accounts AS sas',
    )
    return {r['id']: dict(r) for r in rows}


def test_gcp_firewall_policy_rules_load_and_cleanup(neo4j_session):
    neo4j_session.run('MATCH (n) DETACH DELETE n').consume()
    _seed_tenants(neo4j_session)
    # NOROUTE's call is refused: it gets no rules and keeps VPC-rules-only behaviour.
    _sync_policies(neo4j_session, {MAIN: MAIN_POLICIES})
    rules = _policy_rules(neo4j_session)
    assert len(rules) == 4 and {r['vpc'] for r in rules.values()} == {MAIN_URI}
    org_deny = rules[f'{MAIN_URI}/firewallPolicies/9001/rules/100']
    assert (org_deny['action'], org_deny['type'], org_deny['ord']) == ('deny', 'HIERARCHY', 0)
    assert org_deny['entries'] == ['tcp:443'] and org_deny['sas'] == [BLOCKED_SA]
    assert rules[f'{MAIN_URI}/firewallPolicies/main-netpol/rules/10']['ord'] == 1

    _sync_policies(neo4j_session, {MAIN: {'firewallPolicys': []}}, tag=TAG + 1)
    assert _policy_rules(neo4j_session) == {}


def test_gcp_firewall_policies_end_to_end(neo4j_session):
    _build(neo4j_session)
    _load_instances(
        neo4j_session, [
            _instance(PROJECT, 'org-blocked', MAIN, tags=['web'], nat_ip='34.0.1.1', sa=BLOCKED_SA),
            _instance(PROJECT, 'org-opened', MAIN, nat_ip='34.0.1.2', sa=OPENED_SA),
            _instance(PROJECT, 'netpol-after', MAIN, tags=['web'], nat_ip='34.0.1.3', sa=NETPOL_SA),
            _instance(PROJECT, 'locked-db', MAIN, tags=['db'], sa=LOCKED_DB_SA),
        ],
    )
    _sync_policies(neo4j_session, {MAIN: MAIN_POLICIES})
    exposure_layers.run(neo4j_session, PARAMS)
    s = neo4j_session

    # Scenario 8: the VPC rule web-443 admits it, the org policy's deny wins.
    blocked = _props(s, 'org-blocked')
    assert blocked['public_reasons'] == ['external_ip'] and blocked['internet_reachable'] is False
    assert json.loads(blocked['exposure_blocked_by']) == [
        {'hop': 'firewall_policy', 'id': '9001', 'reason': 'denied', 'detail': 'HIERARCHY'},
    ]
    # No VPC rule opens 8443; the org allow does, before the implied deny.
    assert _props(s, 'org-opened')['internet_reachable_ports'] == ['tcp:8443-8443']
    # Default enforcement order: the VPC allow decides before the network policy's deny is reached.
    assert _props(s, 'netpol-after')['internet_reachable_ports'] == ['tcp:443-443']
    assert _props(s, 'open')['internet_reachable_ports'] == ['tcp:443-443']

    edges = _edges(s)
    assert edges[('app', 'db')] == (['tcp:5432-5432'], 'firewall_source_tag_or_sa')
    assert ('app', 'locked-db') not in edges


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
