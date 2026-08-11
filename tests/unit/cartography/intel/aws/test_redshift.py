from cartography.intel.aws.redshift import filter_active_redshift_reserved_nodes


def test_filter_active_redshift_reserved_nodes_keeps_active_only():
    nodes = [
        {'ReservedNodeId': 'rs-active', 'State': 'active'},
        {'ReservedNodeId': 'rs-retired', 'State': 'retired'},
        {'ReservedNodeId': 'rs-payment-failed', 'State': 'payment-failed'},
        {'ReservedNodeId': 'rs-missing-state'},
    ]

    filtered = filter_active_redshift_reserved_nodes(nodes)

    assert [n['ReservedNodeId'] for n in filtered] == ['rs-active']


def test_filter_active_redshift_reserved_nodes_empty():
    assert filter_active_redshift_reserved_nodes([]) == []
