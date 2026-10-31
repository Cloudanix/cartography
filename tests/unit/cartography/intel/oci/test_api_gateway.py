from unittest.mock import MagicMock

from cartography.intel.oci import api_gateway


def test_transform_gateways():
    rows = api_gateway.transform_gateways(
        [
            {
                'id': 'ocid1.apigateway.oc1.phx.a', 'endpoint-type': 'PUBLIC', 'subnet-id': 'subnet-a',
                'network-security-group-ids': ['nsg-a'], 'hostname': 'abc.apigateway.us-phoenix-1.oci.customer-oci.com',
            },
            {'display-name': 'no id'},
        ],
        'us-phoenix-1',
    )
    assert [(r['id'], r['endpoint_type'], r['subnet_id'], r['nsg_ids']) for r in rows] == [
        ('ocid1.apigateway.oc1.phx.a', 'PUBLIC', 'subnet-a', ['nsg-a']),
    ]
    assert rows[0]['consolelink'].endswith('ocid1.apigateway.oc1.phx.a?region=us-phoenix-1')


def test_get_gateway_list_data_returns_empty_on_error(monkeypatch):
    list_all = MagicMock(side_effect=api_gateway.oci.exceptions.ServiceError(404, 'NotAuthorizedOrNotFound', {}, 'x'))
    monkeypatch.setattr(api_gateway.oci.pagination, 'list_call_get_all_results', list_all)

    assert api_gateway.get_gateway_list_data(MagicMock(), 'compartment') == []
    assert list_all.call_args.kwargs == {'compartment_id': 'compartment', 'lifecycle_state': 'ACTIVE'}
