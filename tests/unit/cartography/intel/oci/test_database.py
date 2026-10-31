from unittest.mock import MagicMock

from cartography.intel.oci import database


def _vnic_response(vnic_id, public_ip):
    data = MagicMock()
    data.__str__.return_value = (
        f'{{"id": "{vnic_id}", "public_ip": "{public_ip}", "nsg_ids": ["nsg-1"], "subnet_id": "subnet-1"}}'
    )
    return MagicMock(data=data)


def test_get_db_node_vnics_fetches_each_primary_vnic_once():
    network_client = MagicMock()
    network_client.get_vnic.side_effect = lambda vnic_id: _vnic_response(vnic_id, '203.0.113.10')
    db_nodes = [
        {'id': 'node-1', 'vnic_id': 'vnic-1', 'backup_vnic_id': 'backup-vnic-1'},
        {'id': 'node-2', 'vnic_id': 'vnic-1'},
        {'id': 'node-3', 'vnic_id': None},
    ]

    vnics = database.get_db_node_vnics(network_client, db_nodes)

    network_client.get_vnic.assert_called_once_with('vnic-1')
    assert [(v['id'], v['public-ip'], v['nsg-ids']) for v in vnics] == [('vnic-1', '203.0.113.10', ['nsg-1'])]


def test_get_db_node_vnics_skips_vnics_it_cannot_read():
    # network.get_vnic_data logs and returns {} on a ServiceError (e.g. missing VNIC_READ).
    network_client = MagicMock()
    network_client.get_vnic.side_effect = database.oci.exceptions.ServiceError(404, 'NotAuthorizedOrNotFound', {}, 'x')

    assert database.get_db_node_vnics(network_client, [{'id': 'node-1', 'vnic_id': 'vnic-1'}]) == []


def test_sync_db_systems_loads_db_node_vnics(monkeypatch):
    system = {'id': 'sys-1', 'lifecycle-state': 'AVAILABLE'}
    node = {'id': 'node-1', 'lifecycle-state': 'AVAILABLE', 'db-system-id': 'sys-1', 'vnic-id': 'vnic-1'}
    monkeypatch.setattr(database, 'get_db_system_list_data', lambda *a: {'DbSystems': [system]})
    monkeypatch.setattr(database, 'get_db_home_list_data', lambda *a: {'DbHomes': []})
    monkeypatch.setattr(database, 'get_db_node_list_data', lambda *a: {'DbNodes': [node]})
    for loader in ('load_db_systems', 'load_db_nodes'):
        monkeypatch.setattr(database, loader, MagicMock())
    network_client = MagicMock()
    network_client.get_vnic.side_effect = lambda vnic_id: _vnic_response(vnic_id, '203.0.113.10')
    monkeypatch.setattr(database.oci.core, 'VirtualNetworkClient', MagicMock(return_value=network_client))
    load_db_node_vnics = MagicMock()
    monkeypatch.setattr(database, 'load_db_node_vnics', load_db_node_vnics)

    database.sync_db_systems(MagicMock(), MagicMock(), 'compartment', 'us-phoenix-1', 1)

    network_client.base_client.set_region.assert_called_once_with('us-phoenix-1')
    vnics = load_db_node_vnics.call_args.args[1]
    assert [v['id'] for v in vnics] == ['vnic-1']
