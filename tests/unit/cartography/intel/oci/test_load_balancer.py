from unittest.mock import MagicMock

from cartography.intel.oci import load_balancer

REGION = 'us-phoenix-1'


def test_transform_load_balancers():
    rows = load_balancer.transform_load_balancers(
        [{
            'id': 'ocid1.loadbalancer.oc1.phx.a',
            'is-private': False,
            'ip-addresses': [{'ip-address': '203.0.113.60', 'is-public': True}],
            'subnet-ids': ['subnet-a', 'subnet-b'],
            'network-security-group-ids': ['nsg-a'],
            'listeners': {'https': {'port': 443, 'protocol': 'HTTP'}, 'grpc': {'port': 8443, 'protocol': 'GRPC'}},
            'backend-sets': {
                'web': {'backends': [{'ip-address': '10.0.1.5'}, {'ip-address': '10.0.1.6'}]},
            },
        }],
        REGION,
    )
    row = rows[0]
    assert row['is_private'] is False
    assert row['public_ip_addresses'] == ['203.0.113.60']
    assert (row['subnet_ids'], row['nsg_ids']) == (['subnet-a', 'subnet-b'], ['nsg-a'])
    # Every Load Balancer protocol (HTTP, HTTP2, TCP, GRPC) runs over TCP.
    assert row['listener_targets'] == ['6:443', '6:8443']
    assert (row['backend_ips'], row['backend_target_ids']) == (['10.0.1.5', '10.0.1.6'], [])
    assert row['consolelink'].endswith('ocid1.loadbalancer.oc1.phx.a?region=us-phoenix-1')


def test_transform_network_load_balancers():
    rows = load_balancer.transform_network_load_balancers(
        [{
            'id': 'ocid1.networkloadbalancer.oc1.phx.b',
            'is-private': False,
            'subnet-id': 'subnet-a',
            'listeners': {
                'dns': {'port': 53, 'protocol': 'TCP_AND_UDP'},
                # Port 0 accepts every port; ANY forwards every protocol.
                'all': {'port': 0, 'protocol': 'ANY'},
            },
            'backend-sets': {
                'pool': {'backends': [{'target-id': 'ocid1.instance.oc1.phx.i'}, {'ip-address': '10.0.2.7'}]},
            },
        }],
        REGION,
    )
    row = rows[0]
    assert row['subnet_ids'] == ['subnet-a']
    assert row['listener_targets'] == ['17:53', '6:53', 'any:0']
    assert (row['backend_ips'], row['backend_target_ids']) == (['10.0.2.7'], ['ocid1.instance.oc1.phx.i'])


def test_list_calls_return_empty_on_error(monkeypatch):
    list_all = MagicMock(side_effect=load_balancer.oci.exceptions.ServiceError(404, 'NotAuthorizedOrNotFound', {}, 'x'))
    monkeypatch.setattr(load_balancer.oci.pagination, 'list_call_get_all_results', list_all)

    assert load_balancer.get_load_balancer_list_data(MagicMock(), 'compartment') == []
    assert load_balancer.get_network_load_balancer_list_data(MagicMock(), 'compartment') == []
    expected = {'compartment_id': 'compartment', 'lifecycle_state': 'ACTIVE'}
    assert [c.kwargs for c in list_all.call_args_list] == [expected, expected]


def test_sync_load_balancers_loads_both_kinds(monkeypatch):
    monkeypatch.setattr(load_balancer, 'get_load_balancer_list_data', lambda *a: [{'id': 'lb-1'}])
    monkeypatch.setattr(load_balancer, 'get_network_load_balancer_list_data', lambda *a: [{'id': 'nlb-1'}])
    load = MagicMock()
    monkeypatch.setattr(load_balancer, 'load_load_balancers', load)
    monkeypatch.setattr(load_balancer.tags, 'sync_tags', MagicMock())

    load_balancer.sync_load_balancers(MagicMock(), MagicMock(), MagicMock(), 'compartment', REGION, 1, {})

    assert [(c.args[2], c.args[1][0]['id']) for c in load.call_args_list] == [
        ('OCILoadBalancer', 'lb-1'), ('OCINetworkLoadBalancer', 'nlb-1'),
    ]
