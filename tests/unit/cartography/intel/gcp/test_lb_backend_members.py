import json
from unittest.mock import MagicMock
from unittest.mock import patch

from googleapiclient import discovery
from googleapiclient.errors import HttpError
from googleapiclient.http import HttpMockSequence

import cartography.intel.gcp
from cartography.intel.gcp import loadbalancer

API = 'https://www.googleapis.com/compute/v1'
ZONE_P1 = 'projects/p1/zones/us-east1-b'
REGION_P1 = 'projects/p1/regions/us-east1'
PARAMS = {'UPDATE_TAG': 42, 'GCP_PROJECT_ID': 'p1', 'WORKSPACE_ID': 'ws', 'GCP_ORGANIZATION_ID': 'org'}


def _sync_members(groups, client):
    """Run the post-sync step with the given external backend groups; return what it loaded."""
    with patch.object(loadbalancer, 'get_external_backend_groups', return_value=groups), \
            patch.object(loadbalancer, 'load_instance_group_members') as load, \
            patch.object(loadbalancer, 'run_cleanup_job') as cleanup:
        loadbalancer.sync_external_backend_members(MagicMock(), client, 'p1', PARAMS)
    cleanup.assert_called_once()
    return load.call_args.args[1]


def test_members_are_listed_only_for_zonal_instance_groups_of_this_project():
    client = MagicMock()
    igs = client.instanceGroups.return_value
    page_1 = {'items': [{'instance': f'{API}/projects/p1/zones/us-east1-b/instances/node-1'}]}
    page_2 = {'items': [{'instance': f'{API}/projects/p1/zones/us-east1-b/instances/node-2'}, {'status': 'RUNNING'}]}
    igs.listInstances.return_value.execute.side_effect = [page_1, page_2]
    igs.listInstances_next.side_effect = [igs.listInstances.return_value, None]

    members = _sync_members(
        [
            'projects/p1/zones/us-east1-b/instanceGroups/k8s-ig--abc',
            # Regional groups are always managed (PART_OF); NEGs and other projects' groups are not listed here.
            'projects/p1/regions/us-east1/instanceGroups/regional-mig',
            'projects/p1/zones/us-east1-b/networkEndpointGroups/neg',
            'projects/other/zones/us-east1-b/instanceGroups/foreign',
        ],
        client,
    )

    igs.listInstances.assert_called_once_with(
        project='p1', zone='us-east1-b', instanceGroup='k8s-ig--abc', body={'instanceState': 'ALL'},
    )
    group = 'projects/p1/zones/us-east1-b/instanceGroups/k8s-ig--abc'
    assert members == [
        {'group': group, 'instance': 'projects/p1/zones/us-east1-b/instances/node-1'},
        {'group': group, 'instance': 'projects/p1/zones/us-east1-b/instances/node-2'},
    ]


def test_unreadable_instance_group_leaves_its_members_unresolved():
    client = MagicMock()
    client.instanceGroups.return_value.listInstances.return_value.execute.side_effect = HttpError(
        MagicMock(status=403), b'{"error": {"code": 403}}',
    )

    members = _sync_members(['projects/p1/zones/us-east1-b/instanceGroups/denied'], client)

    assert members == []


def test_no_external_backend_groups_means_no_api_calls():
    client = MagicMock()

    assert _sync_members([], client) == []
    client.instanceGroups.assert_not_called()


def _sync_project(requested):
    """Run _sync_single_project sequentially with stub services; return the call order."""
    order = []
    services = {
        name: (lambda name: lambda *_: order.append(name))(name) for name in ('compute', 'cloudcdn', 'loadbalancer')
    }
    with patch.dict('os.environ', {'LOCAL_RUN': '1'}), \
            patch.object(cartography.intel.gcp, 'RESOURCE_FUNCTIONS', services), \
            patch.object(cartography.intel.gcp, 'get_all_regions', return_value=['us-central1']), \
            patch.object(cartography.intel.gcp.compute, 'sync_gke_node_links'), \
            patch.object(
                cartography.intel.gcp.loadbalancer, 'sync_external_backend_members',
                side_effect=lambda *_: order.append('members'),
            ):
        config = MagicMock()
        config.params = {}
        cartography.intel.gcp._sync_single_project(
            neo4j_session=MagicMock(),
            resources=MagicMock(),
            requested_syncs=requested,
            project_id='p1',
            gcp_update_tag=42,
            common_job_parameters={**PARAMS, 'service_labels': []},
            config=config,
        )
    return order


def test_project_sync_resolves_backend_members_after_the_parallel_syncs():
    order = _sync_project(['loadbalancer', 'cloudcdn', 'compute'])

    assert order[-1] == 'members'


def test_project_sync_skips_backend_members_without_load_balancer_syncs():
    assert 'members' not in _sync_project(['compute'])


def _pages(collection, method, pages):
    """collection.<method>(...).execute() returns each page in turn; <method>_next ends after the last."""
    request = MagicMock()
    request.execute.side_effect = pages
    getattr(collection, method).return_value = request
    getattr(collection, f'{method}_next').side_effect = [request] * (len(pages) - 1) + [None]


def test_network_endpoint_groups_come_from_every_scope_once():
    client = MagicMock()
    zonal = {
        'name': 'k8s1-neg', 'networkEndpointType': 'GCE_VM_IP_PORT', 'size': 3, 'defaultPort': 8080,
        'selfLink': f'{API}/projects/p1/zones/us-east1-b/networkEndpointGroups/k8s1-neg',
        'zone': f'{API}/projects/p1/zones/us-east1-b', 'network': f'{API}/projects/p1/global/networks/default',
    }
    run_neg = {
        'name': 'run-neg', 'networkEndpointType': 'SERVERLESS', 'cloudRun': {'service': 'web'},
        'selfLink': f'{API}/projects/p1/regions/us-east1/networkEndpointGroups/run-neg',
        'region': f'{API}/projects/p1/regions/us-east1',
    }
    fn_neg = {
        'name': 'fn-neg', 'networkEndpointType': 'SERVERLESS', 'cloudFunction': {'urlMask': '/<function>'},
        'selfLink': f'{API}/projects/p1/regions/europe-west1/networkEndpointGroups/fn-neg',
        'region': f'{API}/projects/p1/regions/europe-west1',
    }
    internet = {
        'name': 'internet-neg', 'networkEndpointType': 'INTERNET_FQDN_PORT',
        'selfLink': f'{API}/projects/p1/global/networkEndpointGroups/internet-neg',
    }
    # The aggregated list may also carry regional scopes: those NEGs must not be loaded twice.
    _pages(
        client.networkEndpointGroups.return_value, 'aggregatedList', [
            {'items': {'zones/us-east1-b': {'networkEndpointGroups': [zonal]}, 'zones/us-east1-c': {'warning': {}}}},
            {'items': {'regions/us-east1': {'networkEndpointGroups': [run_neg]}}},
        ],
    )
    _pages(client.globalNetworkEndpointGroups.return_value, 'list', [{'items': [internet]}])
    regional = client.regionNetworkEndpointGroups.return_value

    def region_list(project, region):
        request = MagicMock()
        if region == 'asia-south1':
            request.execute.side_effect = HttpError(MagicMock(status=403), b'{"error": {"code": 403}}')
        else:
            request.execute.return_value = {'items': {'us-east1': [run_neg], 'europe-west1': [fn_neg]}[region]}
        return request
    regional.list.side_effect = region_list
    regional.list_next.return_value = None

    negs = loadbalancer.transform_network_endpoint_groups(
        loadbalancer.get_network_endpoint_groups(client, 'p1', ['us-east1', 'europe-west1', 'asia-south1']), 'p1',
    )

    by_name = {n['name']: n for n in negs}
    assert sorted(by_name) == ['fn-neg', 'internet-neg', 'k8s1-neg', 'run-neg']
    client.networkEndpointGroups.return_value.aggregatedList.assert_called_once_with(
        project='p1',
    )
    k8s = by_name['k8s1-neg']
    assert (k8s['id'], k8s['zone'], k8s['region'], k8s['network']) == (
        'projects/p1/zones/us-east1-b/networkEndpointGroups/k8s1-neg', 'us-east1-b', 'us-east1',
        'projects/p1/global/networks/default',
    )
    assert (k8s['network_endpoint_type'], k8s['size'], k8s['default_port']) == ('GCE_VM_IP_PORT', 3, 8080)
    run = by_name['run-neg']
    assert (run['id'], run['zone'], run['region'], run['cloud_run_service'], run['consolelink']) == (
        'projects/p1/regions/us-east1/networkEndpointGroups/run-neg', None, 'us-east1', 'web', None,
    )
    assert (by_name['fn-neg']['cloud_function'], by_name['fn-neg']['url_mask']) == (None, '/<function>')
    assert by_name['internet-neg']['region'] == 'global'


def test_vm_neg_endpoints_are_grouped_per_instance():
    client = MagicMock()
    negs = client.networkEndpointGroups.return_value
    _pages(
        negs, 'listNetworkEndpoints', [
            {
                'items': [
                    {'networkEndpoint': {'instance': 'node-1', 'ipAddress': '10.4.0.5', 'port': 8080}},
                    {'networkEndpoint': {'instance': 'node-1', 'ipAddress': '10.4.0.6', 'port': 8080}},
                ],
            },
            {
                'items': [
                    {'networkEndpoint': {'instance': f'{API}/{ZONE_P1}/instances/node-2', 'ipAddress': '10.4.1.2'}},
                    # No instance: not a VM endpoint.
                    {'networkEndpoint': {'ipAddress': '203.0.113.1', 'port': 443}},
                ],
            },
        ],
    )

    endpoints = loadbalancer.get_neg_vm_endpoints(client, 'p1', 'us-east1-b', 'k8s1-neg')

    negs.listNetworkEndpoints.assert_called_once_with(
        project='p1', zone='us-east1-b', networkEndpointGroup='k8s1-neg', body={},
    )
    neg = 'projects/p1/zones/us-east1-b/networkEndpointGroups/k8s1-neg'
    assert endpoints == [
        {
            'instance': 'projects/p1/zones/us-east1-b/instances/node-1', 'neg': neg,
            'ip_addresses': ['10.4.0.5', '10.4.0.6'], 'ports': [8080],
        },
        {
            'instance': 'projects/p1/zones/us-east1-b/instances/node-2', 'neg': neg,
            'ip_addresses': ['10.4.1.2'], 'ports': [],
        },
    ]


def test_unreadable_neg_leaves_its_endpoints_unresolved():
    client = MagicMock()
    client.networkEndpointGroups.return_value.listNetworkEndpoints.return_value.execute.side_effect = HttpError(
        MagicMock(status=403), b'{"error": {"code": 403}}',
    )

    assert loadbalancer.get_neg_vm_endpoints(client, 'p1', 'us-east1-b', 'denied') == []


def test_endpoints_are_listed_only_for_external_zonal_vm_negs():
    client = MagicMock()
    groups = ['projects/p1/zones/us-east1-b/networkEndpointGroups/k8s1-neg']
    with patch.object(loadbalancer, 'get_external_backend_groups', return_value=groups), \
            patch.object(loadbalancer, 'get_external_vm_negs', return_value=groups) as vm_negs, \
            patch.object(loadbalancer, 'get_neg_vm_endpoints', return_value=[{'instance': 'i'}]) as list_endpoints, \
            patch.object(loadbalancer, 'load_instance_group_members'), \
            patch.object(loadbalancer, 'load_neg_vm_endpoints') as load, \
            patch.object(loadbalancer, 'link_backend_services_to_negs') as link, \
            patch.object(loadbalancer, 'run_cleanup_job'):
        loadbalancer.sync_external_backend_members(MagicMock(), client, 'p1', PARAMS)

    assert vm_negs.call_args.args[1:] == ('p1', groups)
    list_endpoints.assert_called_once_with(client, 'p1', 'us-east1-b', 'k8s1-neg')
    assert load.call_args.args[1] == [{'instance': 'i'}]
    link.assert_called_once()


def test_ssl_policies_include_regional_ones_from_the_aggregated_list():
    client = MagicMock()
    _pages(
        client.sslPolicies.return_value, 'aggregatedList', [
            {
                'items': {
                    'global': {'sslPolicies': [{'name': 'modern', 'minTlsVersion': 'TLS_1_2'}]},
                    'regions/us-east1': {
                        'sslPolicies': [
                            {'name': 'regional', 'minTlsVersion': 'TLS_1_0', 'region': f'{API}/{REGION_P1}'},
                        ],
                    },
                },
            },
            {'items': {'regions/europe-west1': {'warning': {'code': 'NO_RESULTS_ON_PAGE'}}}},
        ],
    )
    # The global-only list call (before regional policies) returns a single empty page.
    client.sslPolicies.return_value.list.return_value.execute.return_value = {}
    client.sslPolicies.return_value.list_next.return_value = None

    policies = loadbalancer.transform_ssl_policies(loadbalancer.get_ssl_policies(client, 'p1', PARAMS), 'p1')

    client.sslPolicies.return_value.aggregatedList.assert_called_once_with(project='p1')
    assert sorted((p['id'], p['region']) for p in policies) == [
        ('projects/p1/global/sslPolicies/modern', 'global'),
        ('projects/p1/regions/us-east1/sslPolicies/regional', 'us-east1'),
    ]


def _discovery_compute(*bodies):
    """A real compute client built from the discovery doc bundled with googleapiclient (what prod uses), so
    unknown query parameters raise TypeError just like in prod; each request answers with the next body."""
    responses = [({'status': '200'}, json.dumps(body)) for body in bodies]
    return discovery.build('compute', 'v1', http=HttpMockSequence(responses), static_discovery=True)


def test_aggregated_lists_only_use_parameters_of_the_bundled_discovery_doc():
    neg = {'name': 'neg', 'selfLink': f'{API}/{ZONE_P1}/networkEndpointGroups/neg'}
    client = _discovery_compute(
        {'items': {'global': {'sslPolicies': [{'name': 'modern'}]}}},
        {'items': {'zones/us-east1-b': {'networkEndpointGroups': [neg]}}},
        {},
    )

    assert [p['name'] for p in loadbalancer.get_ssl_policies(client, 'p1', PARAMS)] == ['modern']
    assert [n['name'] for n in loadbalancer.get_network_endpoint_groups(client, 'p1', [])] == ['neg']
