from unittest.mock import MagicMock

from cartography.intel.oci import network


def test_is_internet_ingress_rule():
    assert network.is_internet_ingress_rule({'protocol': '6', 'source': '0.0.0.0/0'})
    assert network.is_internet_ingress_rule({'protocol': 'all', 'source': '::/0'})
    assert network.is_internet_ingress_rule({'protocol': '17', 'source': '0.0.0.0/0', 'direction': 'INGRESS'})
    # Path-MTU ICMP from anywhere (in every Default Security List) reaches no service.
    assert not network.is_internet_ingress_rule({'protocol': '1', 'source': '0.0.0.0/0'})
    assert not network.is_internet_ingress_rule({'protocol': '58', 'source': '::/0'})
    assert not network.is_internet_ingress_rule({'protocol': '6', 'source': '10.0.0.0/16'})
    assert not network.is_internet_ingress_rule({'protocol': '6', 'source': 'ocid1.networksecuritygroup.oc1..x'})
    assert not network.is_internet_ingress_rule({'protocol': '6', 'source': None})
    # An NSG egress rule has a destination, not a source, but guard the direction anyway.
    assert not network.is_internet_ingress_rule({'protocol': '6', 'source': '0.0.0.0/0', 'direction': 'EGRESS'})


def test_internet_ingress_port_range():
    def tcp(lo, hi):
        return {'destination-port-range': {'min': lo, 'max': hi}}

    assert network.internet_ingress_port_range({'protocol': '6', 'source': '0.0.0.0/0', 'tcp-options': tcp(443, 443)}) \
        == '6:443-443'
    assert network.internet_ingress_port_range(
        {'protocol': '17', 'source': '::/0', 'udp-options': {'destination-port-range': {'min': 53, 'max': 54}}},
    ) == '17:53-54'
    # No destination range: every port of that protocol.
    assert network.internet_ingress_port_range({'protocol': '6', 'source': '0.0.0.0/0', 'tcp-options': None}) \
        == '6:1-65535'
    assert network.internet_ingress_port_range({'protocol': 'all', 'source': '0.0.0.0/0'}) == 'all:1-65535'
    # Only a source-port range: still every destination port.
    assert network.internet_ingress_port_range(
        {'protocol': '6', 'source': '0.0.0.0/0', 'tcp-options': {'source-port-range': {'min': 1024, 'max': 1024}}},
    ) == '6:1-65535'
    assert network.internet_ingress_port_range({'protocol': '6', 'source': '10.0.0.0/8', 'tcp-options': tcp(1, 9)}) \
        is None
    assert network.internet_ingress_port_range({'protocol': '1', 'source': '0.0.0.0/0'}) is None


def test_load_security_lists_records_internet_ingress_port_ranges():
    session = _RecordingSession()
    network.load_security_lists(
        session,
        [
            {
                'id': 'open', 'ingress-security-rules': [
                    {
                        'protocol': '6', 'source': '0.0.0.0/0',
                        'tcp-options': {'destination-port-range': {'min': 22, 'max': 22}},
                    },
                    {'protocol': '6', 'source': '10.0.0.0/16'},
                    {'protocol': '1', 'source': '0.0.0.0/0'},
                ],
            },
            {'id': 'empty'},
        ],
        'tenancy', 'compartment', 'us-phoenix-1', 1,
    )
    assert {r['ocid']: r['internet_ingress_port_ranges'] for r in session.rows} == {'open': ['6:22-22'], 'empty': []}


def test_load_nsg_security_rules_records_internet_ingress_port_range():
    session = _RecordingSession()
    network.load_nsg_security_rules(
        session,
        [
            {
                'id': 'in-https', 'direction': 'INGRESS', 'protocol': '6', 'source': '0.0.0.0/0',
                'tcp-options': {'destination-port-range': {'min': 443, 'max': 443}},
            },
            {'id': 'in-vcn', 'direction': 'INGRESS', 'protocol': '6', 'source': '10.0.0.0/16'},
        ],
        'nsg', 1,
    )
    assert {r['ocid']: r['internet_ingress_port_range'] for r in session.rows} == {
        'in-https': '6:443-443', 'in-vcn': None,
    }


def test_load_security_lists_flags_internet_ingress():
    session = _RecordingSession()
    network.load_security_lists(
        session,
        [
            {'id': 'open', 'ingress-security-rules': [{'protocol': '6', 'source': '0.0.0.0/0'}]},
            {'id': 'mtu-only', 'ingress-security-rules': [{'protocol': '1', 'source': '0.0.0.0/0'}]},
            {'id': 'empty'},
        ],
        'tenancy', 'compartment', 'us-phoenix-1', 1,
    )
    assert {r['ocid']: r['allows_internet_ingress'] for r in session.rows} == {
        'open': True, 'mtu-only': False, 'empty': False,
    }


def test_load_nsg_security_rules_flags_internet_ingress():
    session = _RecordingSession()
    network.load_nsg_security_rules(
        session,
        [
            {'id': 'in-open', 'direction': 'INGRESS', 'protocol': '6', 'source': '0.0.0.0/0'},
            {'id': 'in-vcn', 'direction': 'INGRESS', 'protocol': '6', 'source': '10.0.0.0/16'},
            {'id': 'out-open', 'direction': 'EGRESS', 'protocol': 'all', 'destination': '0.0.0.0/0'},
        ],
        'nsg', 1,
    )
    assert {r['ocid']: r['is_internet_ingress'] for r in session.rows} == {
        'in-open': True, 'in-vcn': False, 'out-open': False,
    }


def test_load_route_tables_records_default_routes_to_internet_gateways():
    igw = 'ocid1.internetgateway.oc1.phx.a'
    session = _RecordingSession()
    network.load_route_tables(
        session,
        [
            {'id': 'igw-default', 'route-rules': [{'destination': '0.0.0.0/0', 'network-entity-id': igw}]},
            {'id': 'igw-v6', 'route-rules': [{'destination': '::/0', 'network-entity-id': igw}]},
            # Deprecated cidrBlock field instead of destination.
            {'id': 'igw-legacy', 'route-rules': [{'cidr-block': '0.0.0.0/0', 'network-entity-id': igw}]},
            {'id': 'igw-partial', 'route-rules': [{'destination': '198.51.100.0/24', 'network-entity-id': igw}]},
            {
                'id': 'nat-default',
                'route-rules': [{'destination': '0.0.0.0/0', 'network-entity-id': 'ocid1.natgateway.oc1.phx.b'}],
            },
            {'id': 'empty'},
        ],
        'tenancy', 'compartment', 'us-phoenix-1', 1,
    )
    assert {r['ocid']: r['default_route_igw_ids'] for r in session.rows} == {
        'igw-default': [igw], 'igw-v6': [igw], 'igw-legacy': [igw],
        'igw-partial': [], 'nat-default': [], 'empty': [],
    }


def test_sync_runs_load_balancer_and_api_gateway_syncs_per_region(monkeypatch):
    for name in dir(network):
        if name.startswith('sync_'):
            monkeypatch.setattr(network, name, MagicMock())
    monkeypatch.setattr(network, 'run_cleanup_job', MagicMock())
    for module, client in (
        (network.oci.logging, 'LoggingManagementClient'),
        (network.oci.load_balancer, 'LoadBalancerClient'),
        (network.oci.network_load_balancer, 'NetworkLoadBalancerClient'),
        (network.oci.apigateway, 'GatewayClient'),
        (network.oci.apigateway, 'DeploymentClient'),
    ):
        monkeypatch.setattr(module, client, MagicMock())
    # A load balancer failure must not stop the API gateway sync.
    sync_lbs = MagicMock(side_effect=RuntimeError('boom'))
    monkeypatch.setattr(network.load_balancer, 'sync_load_balancers', sync_lbs)
    sync_gateways = MagicMock()
    monkeypatch.setattr(network.api_gateway, 'sync_gateways', sync_gateways)

    network.sync(MagicMock(), MagicMock(), 'tenancy', 1, {'OCI_COMPARTMENT_ID': 'comp'}, ['r1', 'r2'])

    assert [c.args[4] for c in sync_lbs.call_args_list] == ['r1', 'r2']
    assert [(c.args[2], c.args[3]) for c in sync_gateways.call_args_list] == [('comp', 'r1'), ('comp', 'r2')]


class _RecordingSession:
    """Captures the rows load_graph_data writes instead of talking to Neo4j."""

    def __init__(self):
        self.rows = []

    def execute_write(self, _tx_fn, _query, DictList, **_kwargs):
        self.rows.extend(DictList)
