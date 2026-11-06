from cartography.intel.aws.elasticsearch import filter_active_elasticsearch_reserved_instances
from cartography.intel.aws.elasticsearch import transform_es_domains


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


def test_transform_es_domains_vpc_domain_is_not_public_facing():
    # describe_elasticsearch_domains returns VPCOptions.VPCId (botocore VPCDerivedInfo).
    domains = transform_es_domains(
        [
            {'DomainName': 'in-vpc', 'VPCOptions': {'VPCId': 'vpc-1', 'SubnetIds': ['subnet-1']}},
            {'DomainName': 'legacy-key', 'VPCOptions': {'VpcId': 'vpc-2'}},
            {'DomainName': 'public', 'Endpoint': 'search-public.us-east-1.es.amazonaws.com'},
            {'DomainName': 'empty-vpc-options', 'VPCOptions': {}},
        ],
        'us-east-1',
        '111111111111',
    )

    assert {d['DomainName']: d['isPublicFacing'] for d in domains} == {
        'in-vpc': False,
        'legacy-key': False,
        'public': True,
        'empty-vpc-options': True,
    }
