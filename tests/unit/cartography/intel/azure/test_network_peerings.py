from cartography.intel.azure.network import connected_peer_ids
from cartography.intel.azure.network import peerings_of


def _peering(name, remote, state='Connected', access=True):
    return {
        'id': f'/hub/virtualNetworkPeerings/{name}', 'name': name, 'remote_virtual_network': {'id': remote},
        'peering_state': state, 'allow_virtual_network_access': access, 'allow_forwarded_traffic': True,
        'allow_gateway_transit': False, 'use_remote_gateways': None,
    }


def test_peerings_of_flattens_and_skips_unreferenced():
    network = {'virtual_network_peerings': [_peering('p1', '/Spoke-A'), {'id': 'p2', 'remote_virtual_network': None}]}
    assert peerings_of(network) == [{
        'id': '/hub/virtualNetworkPeerings/p1', 'name': 'p1', 'remote_network_id': '/Spoke-A',
        'peering_state': 'Connected', 'allow_virtual_network_access': True, 'allow_forwarded_traffic': True,
        'allow_gateway_transit': False, 'use_remote_gateways': None,
    }]


def test_peerings_unknown_stays_none():
    # Key absent from the API response = not read: never "no peerings".
    assert peerings_of({}) is None
    assert connected_peer_ids(None) is None
    assert peerings_of({'virtual_network_peerings': []}) == []


def test_connected_peer_ids_needs_connected_and_access():
    peerings = peerings_of({
        'virtual_network_peerings': [
            _peering('ok', '/Spoke-A'),
            _peering('initiated', '/spoke-b', state='Initiated'),
            _peering('no-access', '/spoke-c', access=False),
            _peering('access-unset', '/spoke-d', access=None),  # API default is allow
        ],
    })
    assert connected_peer_ids(peerings) == ['/spoke-a', '/spoke-d']
