from unittest.mock import MagicMock

from googleapiclient.errors import HttpError

from cartography.intel.gcp import compute
from cartography.intel.gcp import instance_groups

API = 'https://www.googleapis.com/compute/v1/projects/p1'


def _fwd(name, scheme, target=None, backend_service=None, region=None):
    item = {'name': name, 'loadBalancingScheme': scheme, 'selfLink': f'{API}/global/forwardingRules/{name}'}
    if region:
        item['region'] = f'{API}/regions/{region}'
    if target:
        item['target'] = f'{API}/{target}'
    if backend_service:
        item['backendService'] = f'{API}/{backend_service}'
    return item


def _compute_returning(targets):
    """A compute client whose <collection>().get(**kwargs).execute() returns targets[(collection, name)]."""
    client = MagicMock()

    def collection(name):
        def get(**kwargs):
            key = (name, next(v for k, v in kwargs.items() if k not in ('project', 'region')))
            request = MagicMock()
            if key not in targets:
                request.execute.side_effect = HttpError(MagicMock(status=403), b'{"error": {"code": 403}}')
            else:
                request.execute.return_value = targets[key]
            return request
        api = MagicMock()
        api.get.side_effect = get
        return MagicMock(return_value=api)

    for name in (
        'targetHttpProxies', 'regionTargetHttpProxies', 'targetHttpsProxies', 'regionTargetHttpsProxies',
        'targetSslProxies', 'targetTcpProxies', 'regionTargetTcpProxies', 'targetPools',
    ):
        setattr(client, name, collection(name))
    return client


def test_external_forwarding_rules_resolve_their_target_to_backends():
    response = {
        'id': 'projects/p1/global/forwardingRules',
        'items': [
            _fwd('https-fr', 'EXTERNAL_MANAGED', target='global/targetHttpsProxies/web-https'),
            _fwd('http-fr', 'EXTERNAL', target='regions/us-east1/targetHttpProxies/web-http', region='us-east1'),
            _fwd('ssl-fr', 'EXTERNAL', target='global/targetSslProxies/tls'),
            _fwd('pool-fr', 'EXTERNAL', target='regions/us-east1/targetPools/pool', region='us-east1'),
            _fwd('nlb-fr', 'EXTERNAL', backend_service='regions/us-east1/backendServices/nlb', region='us-east1'),
            _fwd('denied-fr', 'EXTERNAL', target='global/targetHttpsProxies/forbidden'),
            _fwd('internal-fr', 'INTERNAL', target='regions/us-east1/targetPools/pool', region='us-east1'),
        ],
    }
    client = _compute_returning({
        ('targetHttpsProxies', 'web-https'): {
            'urlMap': f'{API}/global/urlMaps/web', 'sslPolicy': f'{API}/global/sslPolicies/modern',
        },
        ('regionTargetHttpProxies', 'web-http'): {'urlMap': f'{API}/regions/us-east1/urlMaps/web-r'},
        ('targetSslProxies', 'tls'): {'service': f'{API}/global/backendServices/tls-be'},
        ('targetPools', 'pool'): {
            'instances': ['https://www.googleapis.com/compute/v1/projects/p1/zones/us-east1-b/instances/vm-1'],
        },
    })

    rules = compute.transform_gcp_forwarding_rules(response)
    compute.resolve_external_lb_backends(client, rules)

    by_name = {r['name']: r for r in rules}
    assert by_name['https-fr']['url_map'] == 'projects/p1/global/urlMaps/web'
    assert by_name['https-fr']['ssl_policy'] == 'projects/p1/global/sslPolicies/modern'
    assert by_name['http-fr']['url_map'] == 'projects/p1/regions/us-east1/urlMaps/web-r'
    assert by_name['ssl-fr']['backend_services'] == ['projects/p1/global/backendServices/tls-be']
    assert by_name['pool-fr']['target_instances'] == ['projects/p1/zones/us-east1-b/instances/vm-1']
    assert by_name['nlb-fr']['backend_services'] == ['projects/p1/regions/us-east1/backendServices/nlb']
    # Unreadable target: the rule keeps no backends (it is still public itself in the analysis job).
    assert by_name['denied-fr']['url_map'] is None
    assert by_name['denied-fr']['backend_services'] == []
    # Internal load balancers are not resolved at all (no API call).
    assert 'url_map' not in by_name['internal-fr']
    client.targetPools.return_value.get.assert_called_once_with(project='p1', region='us-east1', targetPool='pool')


def test_url_map_lists_every_backend_it_routes_to():
    url_map = {
        'defaultService': f'{API}/global/backendServices/default',
        'pathMatchers': [{
            'defaultService': f'{API}/global/backendBuckets/static',
            'pathRules': [{'service': f'{API}/global/backendServices/api'}],
            'routeRules': [{'service': f'{API}/global/backendServices/api'}, {'urlRedirect': {}}],
        }],
    }
    assert compute.url_map_backend_refs(url_map) == [
        'projects/p1/global/backendServices/default',
        'projects/p1/global/backendBuckets/static',
        'projects/p1/global/backendServices/api',
    ]
    assert compute.url_map_backend_refs({'defaultUrlRedirect': {}}) == []


def test_backend_service_lists_its_backend_groups():
    service = {
        'backends': [
            {'group': f'{API}/zones/us-east1-b/instanceGroups/web-ig'},
            {'group': f'{API}/zones/us-east1-b/networkEndpointGroups/neg'},
        ],
    }
    assert compute.backend_group_refs(service) == [
        'projects/p1/zones/us-east1-b/instanceGroups/web-ig',
        'projects/p1/zones/us-east1-b/networkEndpointGroups/neg',
    ]


def test_managed_instance_group_keeps_the_instance_group_it_manages():
    client = MagicMock()
    client.instanceGroupManagers.return_value.list.return_value.execute.return_value = {
        'items': [{
            'name': 'web', 'selfLink': f'{API}/zones/us-east1-b/instanceGroupManagers/web',
            'instanceGroup': f'{API}/zones/us-east1-b/instanceGroups/web',
        }],
    }
    migs = instance_groups._get_zonal_managed_instance_groups(client, 'p1', [{'name': 'us-east1-b'}])
    assert migs[0]['instance_group'] == 'projects/p1/zones/us-east1-b/instanceGroups/web'
