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


class _RecordingSession:
    """Captures the rows load_graph_data writes instead of talking to Neo4j."""

    def __init__(self):
        self.rows = []

    def execute_write(self, _tx_fn, _query, DictList, **_kwargs):
        self.rows.extend(DictList)
