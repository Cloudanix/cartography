from cartography.intel.aws.elasticsearch import filter_active_elasticsearch_reserved_instances


def test_filter_active_elasticsearch_reserved_instances_keeps_active_only():
    reserved = [
        {'ReservedElasticsearchInstanceId': 'es-active', 'State': 'active'},
        {'ReservedElasticsearchInstanceId': 'es-retired', 'State': 'retired'},
        {'ReservedElasticsearchInstanceId': 'es-payment-pending', 'State': 'payment-pending'},
        {'ReservedElasticsearchInstanceId': 'es-missing-state'},
    ]

    filtered = filter_active_elasticsearch_reserved_instances(reserved)

    assert [r['ReservedElasticsearchInstanceId'] for r in filtered] == ['es-active']


def test_filter_active_elasticsearch_reserved_instances_empty():
    assert filter_active_elasticsearch_reserved_instances([]) == []
